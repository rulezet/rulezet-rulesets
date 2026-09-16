rule TTP_XOR_QUAD_CurrentVersionRun_d5b8 {
  strings:
    $key_d5b8 = { 86 d7 [2] a2 d9 [2] 89 f5 [2] a7 d7 [2] b3 cc [2] bc d6 [2] a2 cb [2] a0 ca [2] bb cc [2] a7 cb [2] bb e4 }

  condition:
    any of them
}