rule TTP_XOR_QUAD_CurrentVersionRun_c1ac {
  strings:
    $key_c1ac = { 92 c3 [2] b6 cd [2] 9d e1 [2] b3 c3 [2] a7 d8 [2] a8 c2 [2] b6 df [2] b4 de [2] af d8 [2] b3 df [2] af f0 }

  condition:
    any of them
}