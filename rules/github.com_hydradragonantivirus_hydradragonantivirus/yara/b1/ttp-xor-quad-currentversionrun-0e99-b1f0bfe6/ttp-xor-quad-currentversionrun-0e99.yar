rule TTP_XOR_QUAD_CurrentVersionRun_0e99 {
  strings:
    $key_0e99 = { 5d f6 [2] 79 f8 [2] 52 d4 [2] 7c f6 [2] 68 ed [2] 67 f7 [2] 79 ea [2] 7b eb [2] 60 ed [2] 7c ea [2] 60 c5 }

  condition:
    any of them
}