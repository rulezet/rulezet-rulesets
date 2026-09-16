rule TTP_XOR_QUAD_CurrentVersionRun_d4a4 {
  strings:
    $key_d4a4 = { 87 cb [2] a3 c5 [2] 88 e9 [2] a6 cb [2] b2 d0 [2] bd ca [2] a3 d7 [2] a1 d6 [2] ba d0 [2] a6 d7 [2] ba f8 }

  condition:
    any of them
}