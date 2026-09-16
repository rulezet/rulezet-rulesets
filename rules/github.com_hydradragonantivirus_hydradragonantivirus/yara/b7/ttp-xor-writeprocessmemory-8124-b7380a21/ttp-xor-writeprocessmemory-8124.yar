rule TTP_XOR_WriteProcessMemory_8124 {
  strings:
    $key_8124 = { d6 56 [2] e4 74 [2] e2 41 [2] cc 41 [2] f3 5d }

  condition:
    any of them
}