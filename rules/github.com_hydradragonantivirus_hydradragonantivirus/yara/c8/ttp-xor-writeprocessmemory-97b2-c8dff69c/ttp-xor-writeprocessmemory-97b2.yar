rule TTP_XOR_WriteProcessMemory_97b2 {
  strings:
    $key_97b2 = { c0 c0 [2] f2 e2 [2] f4 d7 [2] da d7 [2] e5 cb }

  condition:
    any of them
}