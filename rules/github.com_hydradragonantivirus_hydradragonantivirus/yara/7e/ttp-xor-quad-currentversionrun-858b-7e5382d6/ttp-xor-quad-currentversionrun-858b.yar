rule TTP_XOR_QUAD_CurrentVersionRun_858b {
  strings:
    $key_858b = { d6 e4 [2] f2 ea [2] d9 c6 [2] f7 e4 [2] e3 ff [2] ec e5 [2] f2 f8 [2] f0 f9 [2] eb ff [2] f7 f8 [2] eb d7 }

  condition:
    any of them
}