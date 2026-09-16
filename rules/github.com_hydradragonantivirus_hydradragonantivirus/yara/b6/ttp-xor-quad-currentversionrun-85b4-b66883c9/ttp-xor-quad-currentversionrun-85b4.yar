rule TTP_XOR_QUAD_CurrentVersionRun_85b4 {
  strings:
    $key_85b4 = { d6 db [2] f2 d5 [2] d9 f9 [2] f7 db [2] e3 c0 [2] ec da [2] f2 c7 [2] f0 c6 [2] eb c0 [2] f7 c7 [2] eb e8 }

  condition:
    any of them
}