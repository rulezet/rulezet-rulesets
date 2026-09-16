rule TTP_XOR_WriteProcessMemory_8156 {
  strings:
    $key_8156 = { d6 24 [2] e4 06 [2] e2 33 [2] cc 33 [2] f3 2f }

  condition:
    any of them
}