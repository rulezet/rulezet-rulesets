rule TTP_XOR_WriteProcessMemory_49a3 {
  strings:
    $key_49a3 = { 1e d1 [2] 2c f3 [2] 2a c6 [2] 04 c6 [2] 3b da }

  condition:
    any of them
}