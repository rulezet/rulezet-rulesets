rule TTP_XOR_QUAD_CurrentVersionRun_96ad {
  strings:
    $key_96ad = { c5 c2 [2] e1 cc [2] ca e0 [2] e4 c2 [2] f0 d9 [2] ff c3 [2] e1 de [2] e3 df [2] f8 d9 [2] e4 de [2] f8 f1 }

  condition:
    any of them
}