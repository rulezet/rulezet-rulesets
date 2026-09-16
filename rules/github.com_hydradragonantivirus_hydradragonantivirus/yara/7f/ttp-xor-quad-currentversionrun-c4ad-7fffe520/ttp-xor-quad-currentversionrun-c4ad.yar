rule TTP_XOR_QUAD_CurrentVersionRun_c4ad {
  strings:
    $key_c4ad = { 97 c2 [2] b3 cc [2] 98 e0 [2] b6 c2 [2] a2 d9 [2] ad c3 [2] b3 de [2] b1 df [2] aa d9 [2] b6 de [2] aa f1 }

  condition:
    any of them
}