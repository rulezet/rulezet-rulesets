rule TTP_XOR_WriteProcessMemory_93c0 {
  strings:
    $key_93c0 = { c4 b2 [2] f6 90 [2] f0 a5 [2] de a5 [2] e1 b9 }

  condition:
    any of them
}