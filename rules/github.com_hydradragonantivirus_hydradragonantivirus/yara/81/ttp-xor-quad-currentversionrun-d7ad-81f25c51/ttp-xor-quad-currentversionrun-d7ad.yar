rule TTP_XOR_QUAD_CurrentVersionRun_d7ad {
  strings:
    $key_d7ad = { 84 c2 [2] a0 cc [2] 8b e0 [2] a5 c2 [2] b1 d9 [2] be c3 [2] a0 de [2] a2 df [2] b9 d9 [2] a5 de [2] b9 f1 }

  condition:
    any of them
}