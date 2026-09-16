rule TTP_XOR_QUAD_CurrentVersionRun_8486 {
  strings:
    $key_8486 = { d7 e9 [2] f3 e7 [2] d8 cb [2] f6 e9 [2] e2 f2 [2] ed e8 [2] f3 f5 [2] f1 f4 [2] ea f2 [2] f6 f5 [2] ea da }

  condition:
    any of them
}