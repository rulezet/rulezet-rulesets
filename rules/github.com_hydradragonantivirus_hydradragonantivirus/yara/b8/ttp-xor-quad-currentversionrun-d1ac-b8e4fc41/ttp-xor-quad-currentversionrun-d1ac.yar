rule TTP_XOR_QUAD_CurrentVersionRun_d1ac {
  strings:
    $key_d1ac = { 82 c3 [2] a6 cd [2] 8d e1 [2] a3 c3 [2] b7 d8 [2] b8 c2 [2] a6 df [2] a4 de [2] bf d8 [2] a3 df [2] bf f0 }

  condition:
    any of them
}