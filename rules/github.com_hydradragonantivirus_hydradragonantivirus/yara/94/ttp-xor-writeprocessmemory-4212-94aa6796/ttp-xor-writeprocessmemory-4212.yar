rule TTP_XOR_WriteProcessMemory_4212 {
  strings:
    $key_4212 = { 15 60 [2] 27 42 [2] 21 77 [2] 0f 77 [2] 30 6b }

  condition:
    any of them
}