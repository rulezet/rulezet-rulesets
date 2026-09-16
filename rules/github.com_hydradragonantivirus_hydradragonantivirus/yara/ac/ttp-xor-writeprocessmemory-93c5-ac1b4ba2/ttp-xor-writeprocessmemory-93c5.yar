rule TTP_XOR_WriteProcessMemory_93c5 {
  strings:
    $key_93c5 = { c4 b7 [2] f6 95 [2] f0 a0 [2] de a0 [2] e1 bc }

  condition:
    any of them
}