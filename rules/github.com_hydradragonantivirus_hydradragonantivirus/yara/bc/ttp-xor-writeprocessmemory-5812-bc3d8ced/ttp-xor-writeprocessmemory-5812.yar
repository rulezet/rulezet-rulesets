rule TTP_XOR_WriteProcessMemory_5812 {
  strings:
    $key_5812 = { 0f 60 [2] 3d 42 [2] 3b 77 [2] 15 77 [2] 2a 6b }

  condition:
    any of them
}