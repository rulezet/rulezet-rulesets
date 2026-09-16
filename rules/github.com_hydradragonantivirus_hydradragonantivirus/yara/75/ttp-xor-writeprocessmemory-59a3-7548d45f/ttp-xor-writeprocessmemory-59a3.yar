rule TTP_XOR_WriteProcessMemory_59a3 {
  strings:
    $key_59a3 = { 0e d1 [2] 3c f3 [2] 3a c6 [2] 14 c6 [2] 2b da }

  condition:
    any of them
}