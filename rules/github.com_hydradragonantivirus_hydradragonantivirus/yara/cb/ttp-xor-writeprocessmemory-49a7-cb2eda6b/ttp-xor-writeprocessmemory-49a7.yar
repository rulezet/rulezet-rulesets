rule TTP_XOR_WriteProcessMemory_49a7 {
  strings:
    $key_49a7 = { 1e d5 [2] 2c f7 [2] 2a c2 [2] 04 c2 [2] 3b de }

  condition:
    any of them
}