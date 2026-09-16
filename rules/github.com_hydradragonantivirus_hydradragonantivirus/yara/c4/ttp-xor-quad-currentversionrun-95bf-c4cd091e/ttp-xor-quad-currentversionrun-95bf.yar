rule TTP_XOR_QUAD_CurrentVersionRun_95bf {
  strings:
    $key_95bf = { c6 d0 [2] e2 de [2] c9 f2 [2] e7 d0 [2] f3 cb [2] fc d1 [2] e2 cc [2] e0 cd [2] fb cb [2] e7 cc [2] fb e3 }

  condition:
    any of them
}