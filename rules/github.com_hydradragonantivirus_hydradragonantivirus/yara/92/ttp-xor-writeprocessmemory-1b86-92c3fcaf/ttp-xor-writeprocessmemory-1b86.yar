rule TTP_XOR_WriteProcessMemory_1b86 {
  strings:
    $key_1b86 = { 4c f4 [2] 7e d6 [2] 78 e3 [2] 56 e3 [2] 69 ff }

  condition:
    any of them
}