rule TTP_XOR_WriteProcessMemory_8112 {
  strings:
    $key_8112 = { d6 60 [2] e4 42 [2] e2 77 [2] cc 77 [2] f3 6b }

  condition:
    any of them
}