rule TTP_XOR_QUAD_CurrentVersionRun_c889 {
  strings:
    $key_c889 = { 9b e6 [2] bf e8 [2] 94 c4 [2] ba e6 [2] ae fd [2] a1 e7 [2] bf fa [2] bd fb [2] a6 fd [2] ba fa [2] a6 d5 }

  condition:
    any of them
}