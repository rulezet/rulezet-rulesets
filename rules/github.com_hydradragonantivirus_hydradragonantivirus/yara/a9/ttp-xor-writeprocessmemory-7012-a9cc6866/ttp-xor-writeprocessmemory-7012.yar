rule TTP_XOR_WriteProcessMemory_7012 {
  strings:
    $key_7012 = { 27 60 [2] 15 42 [2] 13 77 [2] 3d 77 [2] 02 6b }

  condition:
    any of them
}