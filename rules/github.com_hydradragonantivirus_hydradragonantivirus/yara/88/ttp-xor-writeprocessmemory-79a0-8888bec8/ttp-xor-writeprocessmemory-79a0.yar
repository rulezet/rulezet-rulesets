rule TTP_XOR_WriteProcessMemory_79a0 {
  strings:
    $key_79a0 = { 2e d2 [2] 1c f0 [2] 1a c5 [2] 34 c5 [2] 0b d9 }

  condition:
    any of them
}