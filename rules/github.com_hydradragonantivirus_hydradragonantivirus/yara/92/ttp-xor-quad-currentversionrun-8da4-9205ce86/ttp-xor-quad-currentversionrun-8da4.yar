rule TTP_XOR_QUAD_CurrentVersionRun_8da4 {
  strings:
    $key_8da4 = { de cb [2] fa c5 [2] d1 e9 [2] ff cb [2] eb d0 [2] e4 ca [2] fa d7 [2] f8 d6 [2] e3 d0 [2] ff d7 [2] e3 f8 }

  condition:
    any of them
}