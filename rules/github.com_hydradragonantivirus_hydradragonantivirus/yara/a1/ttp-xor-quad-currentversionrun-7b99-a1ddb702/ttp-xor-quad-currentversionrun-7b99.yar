rule TTP_XOR_QUAD_CurrentVersionRun_7b99 {
  strings:
    $key_7b99 = { 28 f6 [2] 0c f8 [2] 27 d4 [2] 09 f6 [2] 1d ed [2] 12 f7 [2] 0c ea [2] 0e eb [2] 15 ed [2] 09 ea [2] 15 c5 }

  condition:
    any of them
}