rule TTP_XOR_WriteProcessMemory_79a3 {
  strings:
    $key_79a3 = { 2e d1 [2] 1c f3 [2] 1a c6 [2] 34 c6 [2] 0b da }

  condition:
    any of them
}