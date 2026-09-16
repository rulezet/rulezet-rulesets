rule TTP_XOR_QUAD_CurrentVersionRun_d5a5 {
  strings:
    $key_d5a5 = { 86 ca [2] a2 c4 [2] 89 e8 [2] a7 ca [2] b3 d1 [2] bc cb [2] a2 d6 [2] a0 d7 [2] bb d1 [2] a7 d6 [2] bb f9 }

  condition:
    any of them
}