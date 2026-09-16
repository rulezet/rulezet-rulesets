rule TTP_XOR_WriteProcessMemory_8102 {
  strings:
    $key_8102 = { d6 70 [2] e4 52 [2] e2 67 [2] cc 67 [2] f3 7b }

  condition:
    any of them
}