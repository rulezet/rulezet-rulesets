rule TTP_XOR_WriteProcessMemory_83e6 {
  strings:
    $key_83e6 = { d4 94 [2] e6 b6 [2] e0 83 [2] ce 83 [2] f1 9f }

  condition:
    any of them
}