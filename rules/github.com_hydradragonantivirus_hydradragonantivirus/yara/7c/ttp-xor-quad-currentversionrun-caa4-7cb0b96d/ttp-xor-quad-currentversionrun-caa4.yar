rule TTP_XOR_QUAD_CurrentVersionRun_caa4 {
  strings:
    $key_caa4 = { 99 cb [2] bd c5 [2] 96 e9 [2] b8 cb [2] ac d0 [2] a3 ca [2] bd d7 [2] bf d6 [2] a4 d0 [2] b8 d7 [2] a4 f8 }

  condition:
    any of them
}