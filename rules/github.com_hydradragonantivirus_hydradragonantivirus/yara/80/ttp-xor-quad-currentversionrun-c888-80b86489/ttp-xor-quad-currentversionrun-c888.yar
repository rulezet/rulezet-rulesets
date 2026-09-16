rule TTP_XOR_QUAD_CurrentVersionRun_c888 {
  strings:
    $key_c888 = { 9b e7 [2] bf e9 [2] 94 c5 [2] ba e7 [2] ae fc [2] a1 e6 [2] bf fb [2] bd fa [2] a6 fc [2] ba fb [2] a6 d4 }

  condition:
    any of them
}