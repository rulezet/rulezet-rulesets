rule TTP_XOR_QUAD_CurrentVersionRun_c198 {
  strings:
    $key_c198 = { 92 f7 [2] b6 f9 [2] 9d d5 [2] b3 f7 [2] a7 ec [2] a8 f6 [2] b6 eb [2] b4 ea [2] af ec [2] b3 eb [2] af c4 }

  condition:
    any of them
}