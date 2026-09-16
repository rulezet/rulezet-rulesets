rule TTP_XOR_WriteProcessMemory_79a7 {
  strings:
    $key_79a7 = { 2e d5 [2] 1c f7 [2] 1a c2 [2] 34 c2 [2] 0b de }

  condition:
    any of them
}