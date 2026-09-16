rule TTP_XOR_QUAD_CurrentVersionRun_85a6 {
  strings:
    $key_85a6 = { d6 c9 [2] f2 c7 [2] d9 eb [2] f7 c9 [2] e3 d2 [2] ec c8 [2] f2 d5 [2] f0 d4 [2] eb d2 [2] f7 d5 [2] eb fa }

  condition:
    any of them
}