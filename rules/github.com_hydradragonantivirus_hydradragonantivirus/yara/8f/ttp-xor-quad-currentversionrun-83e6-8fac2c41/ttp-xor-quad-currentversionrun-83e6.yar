rule TTP_XOR_QUAD_CurrentVersionRun_83e6 {
  strings:
    $key_83e6 = { d0 89 [2] f4 87 [2] df ab [2] f1 89 [2] e5 92 [2] ea 88 [2] f4 95 [2] f6 94 [2] ed 92 [2] f1 95 [2] ed ba }

  condition:
    any of them
}