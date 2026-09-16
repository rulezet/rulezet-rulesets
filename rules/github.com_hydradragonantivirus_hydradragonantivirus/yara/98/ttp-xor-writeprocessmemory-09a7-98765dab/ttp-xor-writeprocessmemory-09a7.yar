rule TTP_XOR_WriteProcessMemory_09a7 {
  strings:
    $key_09a7 = { 5e d5 [2] 6c f7 [2] 6a c2 [2] 44 c2 [2] 7b de }

  condition:
    any of them
}