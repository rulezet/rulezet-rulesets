rule TTP_XOR_QUAD_CurrentVersionRun_fb99 {
  strings:
    $key_fb99 = { a8 f6 [2] 8c f8 [2] a7 d4 [2] 89 f6 [2] 9d ed [2] 92 f7 [2] 8c ea [2] 8e eb [2] 95 ed [2] 89 ea [2] 95 c5 }

  condition:
    any of them
}