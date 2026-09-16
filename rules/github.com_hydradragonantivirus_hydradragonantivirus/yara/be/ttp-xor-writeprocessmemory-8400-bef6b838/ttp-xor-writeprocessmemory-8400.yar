rule TTP_XOR_WriteProcessMemory_8400 {
  strings:
    $key_8400 = { d3 72 [2] e1 50 [2] e7 65 [2] c9 65 [2] f6 79 }

  condition:
    any of them
}