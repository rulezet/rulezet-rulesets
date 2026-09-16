rule TTP_XOR_WriteProcessMemory_96c5 {
  strings:
    $key_96c5 = { c1 b7 [2] f3 95 [2] f5 a0 [2] db a0 [2] e4 bc }

  condition:
    any of them
}