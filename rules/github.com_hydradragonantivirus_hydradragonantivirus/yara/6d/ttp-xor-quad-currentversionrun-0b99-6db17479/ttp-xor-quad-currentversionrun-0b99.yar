rule TTP_XOR_QUAD_CurrentVersionRun_0b99 {
  strings:
    $key_0b99 = { 58 f6 [2] 7c f8 [2] 57 d4 [2] 79 f6 [2] 6d ed [2] 62 f7 [2] 7c ea [2] 7e eb [2] 65 ed [2] 79 ea [2] 65 c5 }

  condition:
    any of them
}