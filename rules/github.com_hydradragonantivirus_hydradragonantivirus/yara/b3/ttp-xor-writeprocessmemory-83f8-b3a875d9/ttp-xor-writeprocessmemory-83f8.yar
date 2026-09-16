rule TTP_XOR_WriteProcessMemory_83f8 {
  strings:
    $key_83f8 = { d4 8a [2] e6 a8 [2] e0 9d [2] ce 9d [2] f1 81 }

  condition:
    any of them
}