rule TTP_XOR_WriteProcessMemory_09a3 {
  strings:
    $key_09a3 = { 5e d1 [2] 6c f3 [2] 6a c6 [2] 44 c6 [2] 7b da }

  condition:
    any of them
}