rule TTP_XOR_QUAD_CurrentVersionRun_d1ad {
  strings:
    $key_d1ad = { 82 c2 [2] a6 cc [2] 8d e0 [2] a3 c2 [2] b7 d9 [2] b8 c3 [2] a6 de [2] a4 df [2] bf d9 [2] a3 de [2] bf f1 }

  condition:
    any of them
}