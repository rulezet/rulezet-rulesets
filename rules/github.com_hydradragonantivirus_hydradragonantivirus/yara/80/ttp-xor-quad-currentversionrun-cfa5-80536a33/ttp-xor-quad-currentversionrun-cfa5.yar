rule TTP_XOR_QUAD_CurrentVersionRun_cfa5 {
  strings:
    $key_cfa5 = { 9c ca [2] b8 c4 [2] 93 e8 [2] bd ca [2] a9 d1 [2] a6 cb [2] b8 d6 [2] ba d7 [2] a1 d1 [2] bd d6 [2] a1 f9 }

  condition:
    any of them
}