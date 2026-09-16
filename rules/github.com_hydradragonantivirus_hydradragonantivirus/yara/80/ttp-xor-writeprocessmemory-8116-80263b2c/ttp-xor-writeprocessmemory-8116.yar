rule TTP_XOR_WriteProcessMemory_8116 {
  strings:
    $key_8116 = { d6 64 [2] e4 46 [2] e2 73 [2] cc 73 [2] f3 6f }

  condition:
    any of them
}