rule TTP_XOR_QUAD_CurrentVersionRun_85b5 {
  strings:
    $key_85b5 = { d6 da [2] f2 d4 [2] d9 f8 [2] f7 da [2] e3 c1 [2] ec db [2] f2 c6 [2] f0 c7 [2] eb c1 [2] f7 c6 [2] eb e9 }

  condition:
    any of them
}