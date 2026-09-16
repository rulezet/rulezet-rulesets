rule TTP_XOR_QUAD_CurrentVersionRun_c6ad {
  strings:
    $key_c6ad = { 95 c2 [2] b1 cc [2] 9a e0 [2] b4 c2 [2] a0 d9 [2] af c3 [2] b1 de [2] b3 df [2] a8 d9 [2] b4 de [2] a8 f1 }

  condition:
    any of them
}