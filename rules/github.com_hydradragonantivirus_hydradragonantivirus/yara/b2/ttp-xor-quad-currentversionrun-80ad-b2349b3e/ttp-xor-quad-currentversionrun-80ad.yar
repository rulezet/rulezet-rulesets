rule TTP_XOR_QUAD_CurrentVersionRun_80ad {
  strings:
    $key_80ad = { d3 c2 [2] f7 cc [2] dc e0 [2] f2 c2 [2] e6 d9 [2] e9 c3 [2] f7 de [2] f5 df [2] ee d9 [2] f2 de [2] ee f1 }

  condition:
    any of them
}