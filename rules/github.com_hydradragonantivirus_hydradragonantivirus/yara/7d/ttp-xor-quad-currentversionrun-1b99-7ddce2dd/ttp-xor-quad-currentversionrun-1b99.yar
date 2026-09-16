rule TTP_XOR_QUAD_CurrentVersionRun_1b99 {
  strings:
    $key_1b99 = { 48 f6 [2] 6c f8 [2] 47 d4 [2] 69 f6 [2] 7d ed [2] 72 f7 [2] 6c ea [2] 6e eb [2] 75 ed [2] 69 ea [2] 75 c5 }

  condition:
    any of them
}