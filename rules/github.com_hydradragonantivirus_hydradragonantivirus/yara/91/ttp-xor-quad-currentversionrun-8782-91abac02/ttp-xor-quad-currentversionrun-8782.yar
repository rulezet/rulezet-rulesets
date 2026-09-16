rule TTP_XOR_QUAD_CurrentVersionRun_8782 {
  strings:
    $key_8782 = { d4 ed [2] f0 e3 [2] db cf [2] f5 ed [2] e1 f6 [2] ee ec [2] f0 f1 [2] f2 f0 [2] e9 f6 [2] f5 f1 [2] e9 de }

  condition:
    any of them
}