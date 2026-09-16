rule TTP_XOR_WriteProcessMemory_59a7 {
  strings:
    $key_59a7 = { 0e d5 [2] 3c f7 [2] 3a c2 [2] 14 c2 [2] 2b de }

  condition:
    any of them
}