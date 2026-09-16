rule TTP_XOR_WriteProcessMemory_8106 {
  strings:
    $key_8106 = { d6 74 [2] e4 56 [2] e2 63 [2] cc 63 [2] f3 7f }

  condition:
    any of them
}