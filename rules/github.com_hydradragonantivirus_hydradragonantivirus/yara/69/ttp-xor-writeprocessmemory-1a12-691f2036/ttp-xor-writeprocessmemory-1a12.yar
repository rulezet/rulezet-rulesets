rule TTP_XOR_WriteProcessMemory_1a12 {
  strings:
    $key_1a12 = { 4d 60 [2] 7f 42 [2] 79 77 [2] 57 77 [2] 68 6b }

  condition:
    any of them
}