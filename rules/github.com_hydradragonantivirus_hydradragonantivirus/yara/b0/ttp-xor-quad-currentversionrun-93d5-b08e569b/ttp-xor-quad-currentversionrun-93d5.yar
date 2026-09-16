rule TTP_XOR_QUAD_CurrentVersionRun_93d5 {
  strings:
    $key_93d5 = { c0 ba [2] e4 b4 [2] cf 98 [2] e1 ba [2] f5 a1 [2] fa bb [2] e4 a6 [2] e6 a7 [2] fd a1 [2] e1 a6 [2] fd 89 }

  condition:
    any of them
}