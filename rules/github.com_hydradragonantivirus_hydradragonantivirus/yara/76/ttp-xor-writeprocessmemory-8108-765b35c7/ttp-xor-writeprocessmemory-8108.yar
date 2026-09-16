rule TTP_XOR_WriteProcessMemory_8108 {
  strings:
    $key_8108 = { d6 7a [2] e4 58 [2] e2 6d [2] cc 6d [2] f3 71 }

  condition:
    any of them
}