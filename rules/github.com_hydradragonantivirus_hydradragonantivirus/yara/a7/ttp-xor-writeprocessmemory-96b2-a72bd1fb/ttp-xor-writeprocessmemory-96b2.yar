rule TTP_XOR_WriteProcessMemory_96b2 {
  strings:
    $key_96b2 = { c1 c0 [2] f3 e2 [2] f5 d7 [2] db d7 [2] e4 cb }

  condition:
    any of them
}