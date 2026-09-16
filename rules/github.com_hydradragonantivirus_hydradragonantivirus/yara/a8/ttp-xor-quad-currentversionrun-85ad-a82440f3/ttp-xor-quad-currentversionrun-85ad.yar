rule TTP_XOR_QUAD_CurrentVersionRun_85ad {
  strings:
    $key_85ad = { d6 c2 [2] f2 cc [2] d9 e0 [2] f7 c2 [2] e3 d9 [2] ec c3 [2] f2 de [2] f0 df [2] eb d9 [2] f7 de [2] eb f1 }

  condition:
    any of them
}