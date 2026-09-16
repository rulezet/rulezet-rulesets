rule TTP_XOR_QUAD_CurrentVersionRun_d4a5 {
  strings:
    $key_d4a5 = { 87 ca [2] a3 c4 [2] 88 e8 [2] a6 ca [2] b2 d1 [2] bd cb [2] a3 d6 [2] a1 d7 [2] ba d1 [2] a6 d6 [2] ba f9 }

  condition:
    any of them
}