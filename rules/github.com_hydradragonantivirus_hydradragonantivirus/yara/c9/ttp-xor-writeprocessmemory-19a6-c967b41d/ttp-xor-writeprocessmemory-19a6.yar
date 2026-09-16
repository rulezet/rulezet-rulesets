rule TTP_XOR_WriteProcessMemory_19a6 {
  strings:
    $key_19a6 = { 4e d4 [2] 7c f6 [2] 7a c3 [2] 54 c3 [2] 6b df }

  condition:
    any of them
}