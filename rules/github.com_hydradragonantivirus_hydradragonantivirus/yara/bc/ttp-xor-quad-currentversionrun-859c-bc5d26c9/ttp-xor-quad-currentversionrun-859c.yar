rule TTP_XOR_QUAD_CurrentVersionRun_859c {
  strings:
    $key_859c = { d6 f3 [2] f2 fd [2] d9 d1 [2] f7 f3 [2] e3 e8 [2] ec f2 [2] f2 ef [2] f0 ee [2] eb e8 [2] f7 ef [2] eb c0 }

  condition:
    any of them
}