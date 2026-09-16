rule TTP_XOR_WriteProcessMemory_39a3 {
  strings:
    $key_39a3 = { 6e d1 [2] 5c f3 [2] 5a c6 [2] 74 c6 [2] 4b da }

  condition:
    any of them
}