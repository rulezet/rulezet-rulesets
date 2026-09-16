rule TTP_XOR_WriteProcessMemory_95a0 {
  strings:
    $key_95a0 = { c2 d2 [2] f0 f0 [2] f6 c5 [2] d8 c5 [2] e7 d9 }

  condition:
    any of them
}