rule TTP_XOR_WriteProcessMemory_82c5 {
  strings:
    $key_82c5 = { d5 b7 [2] e7 95 [2] e1 a0 [2] cf a0 [2] f0 bc }

  condition:
    any of them
}