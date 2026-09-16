rule TTP_XOR_QUAD_CurrentVersionRun_dd98 {
  strings:
    $key_dd98 = { 8e f7 [2] aa f9 [2] 81 d5 [2] af f7 [2] bb ec [2] b4 f6 [2] aa eb [2] a8 ea [2] b3 ec [2] af eb [2] b3 c4 }

  condition:
    any of them
}