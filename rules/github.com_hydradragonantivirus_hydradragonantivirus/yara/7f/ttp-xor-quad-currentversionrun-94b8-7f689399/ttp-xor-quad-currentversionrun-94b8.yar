rule TTP_XOR_QUAD_CurrentVersionRun_94b8 {
  strings:
    $key_94b8 = { c7 d7 [2] e3 d9 [2] c8 f5 [2] e6 d7 [2] f2 cc [2] fd d6 [2] e3 cb [2] e1 ca [2] fa cc [2] e6 cb [2] fa e4 }

  condition:
    any of them
}