rule TTP_XOR_WriteProcessMemory_49a0 {
  strings:
    $key_49a0 = { 1e d2 [2] 2c f0 [2] 2a c5 [2] 04 c5 [2] 3b d9 }

  condition:
    any of them
}