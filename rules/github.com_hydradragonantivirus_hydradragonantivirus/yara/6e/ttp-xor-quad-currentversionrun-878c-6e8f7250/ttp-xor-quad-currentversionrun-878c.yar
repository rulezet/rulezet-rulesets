rule TTP_XOR_QUAD_CurrentVersionRun_878c {
  strings:
    $key_878c = { d4 e3 [2] f0 ed [2] db c1 [2] f5 e3 [2] e1 f8 [2] ee e2 [2] f0 ff [2] f2 fe [2] e9 f8 [2] f5 ff [2] e9 d0 }

  condition:
    any of them
}