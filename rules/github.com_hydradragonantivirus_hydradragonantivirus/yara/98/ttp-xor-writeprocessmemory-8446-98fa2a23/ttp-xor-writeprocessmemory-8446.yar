rule TTP_XOR_WriteProcessMemory_8446 {
  strings:
    $key_8446 = { d3 34 [2] e1 16 [2] e7 23 [2] c9 23 [2] f6 3f }

  condition:
    any of them
}