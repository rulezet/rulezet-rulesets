rule TTP_XOR_QUAD_CurrentVersionRun_6b99 {
  strings:
    $key_6b99 = { 38 f6 [2] 1c f8 [2] 37 d4 [2] 19 f6 [2] 0d ed [2] 02 f7 [2] 1c ea [2] 1e eb [2] 05 ed [2] 19 ea [2] 05 c5 }

  condition:
    any of them
}