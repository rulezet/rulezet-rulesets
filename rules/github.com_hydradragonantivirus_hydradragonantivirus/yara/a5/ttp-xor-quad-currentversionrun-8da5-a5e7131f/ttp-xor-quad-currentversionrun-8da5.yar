rule TTP_XOR_QUAD_CurrentVersionRun_8da5 {
  strings:
    $key_8da5 = { de ca [2] fa c4 [2] d1 e8 [2] ff ca [2] eb d1 [2] e4 cb [2] fa d6 [2] f8 d7 [2] e3 d1 [2] ff d6 [2] e3 f9 }

  condition:
    any of them
}