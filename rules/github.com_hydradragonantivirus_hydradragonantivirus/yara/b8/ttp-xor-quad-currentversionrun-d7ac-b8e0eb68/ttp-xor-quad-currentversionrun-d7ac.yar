rule TTP_XOR_QUAD_CurrentVersionRun_d7ac {
  strings:
    $key_d7ac = { 84 c3 [2] a0 cd [2] 8b e1 [2] a5 c3 [2] b1 d8 [2] be c2 [2] a0 df [2] a2 de [2] b9 d8 [2] a5 df [2] b9 f0 }

  condition:
    any of them
}