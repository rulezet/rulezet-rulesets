rule TTP_XOR_QUAD_CurrentVersionRun_4e99 {
  strings:
    $key_4e99 = { 1d f6 [2] 39 f8 [2] 12 d4 [2] 3c f6 [2] 28 ed [2] 27 f7 [2] 39 ea [2] 3b eb [2] 20 ed [2] 3c ea [2] 20 c5 }

  condition:
    any of them
}