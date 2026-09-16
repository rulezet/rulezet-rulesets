rule TTP_XOR_WriteProcessMemory_2b86 {
  strings:
    $key_2b86 = { 7c f4 [2] 4e d6 [2] 48 e3 [2] 66 e3 [2] 59 ff }

  condition:
    any of them
}