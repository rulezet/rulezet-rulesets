rule TTP_XOR_QUAD_CurrentVersionRun_94c8 {
  strings:
    $key_94c8 = { c7 a7 [2] e3 a9 [2] c8 85 [2] e6 a7 [2] f2 bc [2] fd a6 [2] e3 bb [2] e1 ba [2] fa bc [2] e6 bb [2] fa 94 }

  condition:
    any of them
}