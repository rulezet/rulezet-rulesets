rule TTP_XOR_QUAD_CurrentVersionRun_c385 {
  strings:
    $key_c385 = { 90 ea [2] b4 e4 [2] 9f c8 [2] b1 ea [2] a5 f1 [2] aa eb [2] b4 f6 [2] b6 f7 [2] ad f1 [2] b1 f6 [2] ad d9 }

  condition:
    any of them
}