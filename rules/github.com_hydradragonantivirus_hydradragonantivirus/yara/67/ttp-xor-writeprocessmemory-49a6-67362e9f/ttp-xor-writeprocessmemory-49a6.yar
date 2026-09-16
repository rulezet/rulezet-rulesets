rule TTP_XOR_WriteProcessMemory_49a6 {
  strings:
    $key_49a6 = { 1e d4 [2] 2c f6 [2] 2a c3 [2] 04 c3 [2] 3b df }

  condition:
    any of them
}