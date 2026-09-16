rule TTP_XOR_QUAD_CurrentVersionRun_d2a5 {
  strings:
    $key_d2a5 = { 81 ca [2] a5 c4 [2] 8e e8 [2] a0 ca [2] b4 d1 [2] bb cb [2] a5 d6 [2] a7 d7 [2] bc d1 [2] a0 d6 [2] bc f9 }

  condition:
    any of them
}