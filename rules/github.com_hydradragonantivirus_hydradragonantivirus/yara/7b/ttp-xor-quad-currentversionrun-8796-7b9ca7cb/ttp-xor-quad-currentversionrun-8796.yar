rule TTP_XOR_QUAD_CurrentVersionRun_8796 {
  strings:
    $key_8796 = { d4 f9 [2] f0 f7 [2] db db [2] f5 f9 [2] e1 e2 [2] ee f8 [2] f0 e5 [2] f2 e4 [2] e9 e2 [2] f5 e5 [2] e9 ca }

  condition:
    any of them
}