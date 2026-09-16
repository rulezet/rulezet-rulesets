rule TTP_XOR_WriteProcessMemory_94b2 {
  strings:
    $key_94b2 = { c3 c0 [2] f1 e2 [2] f7 d7 [2] d9 d7 [2] e6 cb }

  condition:
    any of them
}