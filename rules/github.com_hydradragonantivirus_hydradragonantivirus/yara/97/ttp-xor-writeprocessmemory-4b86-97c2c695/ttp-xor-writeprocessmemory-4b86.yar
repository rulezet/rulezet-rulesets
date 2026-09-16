rule TTP_XOR_WriteProcessMemory_4b86 {
  strings:
    $key_4b86 = { 1c f4 [2] 2e d6 [2] 28 e3 [2] 06 e3 [2] 39 ff }

  condition:
    any of them
}