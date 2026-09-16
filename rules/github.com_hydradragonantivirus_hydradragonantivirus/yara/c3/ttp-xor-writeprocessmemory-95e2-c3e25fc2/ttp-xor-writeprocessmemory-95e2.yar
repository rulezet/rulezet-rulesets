rule TTP_XOR_WriteProcessMemory_95e2 {
  strings:
    $key_95e2 = { c2 90 [2] f0 b2 [2] f6 87 [2] d8 87 [2] e7 9b }

  condition:
    any of them
}