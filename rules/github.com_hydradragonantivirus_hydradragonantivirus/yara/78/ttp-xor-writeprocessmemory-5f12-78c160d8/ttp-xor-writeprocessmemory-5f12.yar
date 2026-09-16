rule TTP_XOR_WriteProcessMemory_5f12 {
  strings:
    $key_5f12 = { 08 60 [2] 3a 42 [2] 3c 77 [2] 12 77 [2] 2d 6b }

  condition:
    any of them
}