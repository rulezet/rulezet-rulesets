rule TTP_XOR_WriteProcessMemory_95f6 {
  strings:
    $key_95f6 = { c2 84 [2] f0 a6 [2] f6 93 [2] d8 93 [2] e7 8f }

  condition:
    any of them
}