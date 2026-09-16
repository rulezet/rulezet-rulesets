rule TTP_XOR_QUAD_CurrentVersionRun_c6ac {
  strings:
    $key_c6ac = { 95 c3 [2] b1 cd [2] 9a e1 [2] b4 c3 [2] a0 d8 [2] af c2 [2] b1 df [2] b3 de [2] a8 d8 [2] b4 df [2] a8 f0 }

  condition:
    any of them
}