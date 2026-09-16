rule TTP_XOR_WriteProcessMemory_93b2 {
  strings:
    $key_93b2 = { c4 c0 [2] f6 e2 [2] f0 d7 [2] de d7 [2] e1 cb }

  condition:
    any of them
}