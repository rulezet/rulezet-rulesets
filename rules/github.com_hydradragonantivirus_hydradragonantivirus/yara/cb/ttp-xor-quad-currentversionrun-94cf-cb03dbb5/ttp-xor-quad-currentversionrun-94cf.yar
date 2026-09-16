rule TTP_XOR_QUAD_CurrentVersionRun_94cf {
  strings:
    $key_94cf = { c7 a0 [2] e3 ae [2] c8 82 [2] e6 a0 [2] f2 bb [2] fd a1 [2] e3 bc [2] e1 bd [2] fa bb [2] e6 bc [2] fa 93 }

  condition:
    any of them
}