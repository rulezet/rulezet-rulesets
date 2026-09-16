rule TTP_XOR_QUAD_CurrentVersionRun_daa5 {
  strings:
    $key_daa5 = { 89 ca [2] ad c4 [2] 86 e8 [2] a8 ca [2] bc d1 [2] b3 cb [2] ad d6 [2] af d7 [2] b4 d1 [2] a8 d6 [2] b4 f9 }

  condition:
    any of them
}