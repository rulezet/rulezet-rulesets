rule TTP_XOR_QUAD_CurrentVersionRun_eb99 {
  strings:
    $key_eb99 = { b8 f6 [2] 9c f8 [2] b7 d4 [2] 99 f6 [2] 8d ed [2] 82 f7 [2] 9c ea [2] 9e eb [2] 85 ed [2] 99 ea [2] 85 c5 }

  condition:
    any of them
}