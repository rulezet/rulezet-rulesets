rule TTP_XOR_WriteProcessMemory_29a3 {
  strings:
    $key_29a3 = { 7e d1 [2] 4c f3 [2] 4a c6 [2] 64 c6 [2] 5b da }

  condition:
    any of them
}