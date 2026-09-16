rule TTP_XOR_WriteProcessMemory_29a6 {
  strings:
    $key_29a6 = { 7e d4 [2] 4c f6 [2] 4a c3 [2] 64 c3 [2] 5b df }

  condition:
    any of them
}