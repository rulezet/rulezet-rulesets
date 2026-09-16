rule TTP_XOR_QUAD_CurrentVersionRun_868b {
  strings:
    $key_868b = { d5 e4 [2] f1 ea [2] da c6 [2] f4 e4 [2] e0 ff [2] ef e5 [2] f1 f8 [2] f3 f9 [2] e8 ff [2] f4 f8 [2] e8 d7 }

  condition:
    any of them
}