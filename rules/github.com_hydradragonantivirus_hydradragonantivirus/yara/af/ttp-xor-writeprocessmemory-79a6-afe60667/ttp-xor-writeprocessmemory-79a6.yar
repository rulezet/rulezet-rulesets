rule TTP_XOR_WriteProcessMemory_79a6 {
  strings:
    $key_79a6 = { 2e d4 [2] 1c f6 [2] 1a c3 [2] 34 c3 [2] 0b df }

  condition:
    any of them
}