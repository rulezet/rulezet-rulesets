rule TTP_XOR_QUAD_CurrentVersionRun_d884 {
  strings:
    $key_d884 = { 8b eb [2] af e5 [2] 84 c9 [2] aa eb [2] be f0 [2] b1 ea [2] af f7 [2] ad f6 [2] b6 f0 [2] aa f7 [2] b6 d8 }

  condition:
    any of them
}