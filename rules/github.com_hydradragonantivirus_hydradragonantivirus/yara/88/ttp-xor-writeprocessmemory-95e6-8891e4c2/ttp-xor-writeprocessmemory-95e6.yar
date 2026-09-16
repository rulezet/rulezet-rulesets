rule TTP_XOR_WriteProcessMemory_95e6 {
  strings:
    $key_95e6 = { c2 94 [2] f0 b6 [2] f6 83 [2] d8 83 [2] e7 9f }

  condition:
    any of them
}