rule TTP_XOR_QUAD_CurrentVersionRun_c384 {
  strings:
    $key_c384 = { 90 eb [2] b4 e5 [2] 9f c9 [2] b1 eb [2] a5 f0 [2] aa ea [2] b4 f7 [2] b6 f6 [2] ad f0 [2] b1 f7 [2] ad d8 }

  condition:
    any of them
}