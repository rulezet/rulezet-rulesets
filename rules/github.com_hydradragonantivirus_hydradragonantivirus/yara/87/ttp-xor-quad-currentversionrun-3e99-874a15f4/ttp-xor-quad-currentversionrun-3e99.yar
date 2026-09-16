rule TTP_XOR_QUAD_CurrentVersionRun_3e99 {
  strings:
    $key_3e99 = { 6d f6 [2] 49 f8 [2] 62 d4 [2] 4c f6 [2] 58 ed [2] 57 f7 [2] 49 ea [2] 4b eb [2] 50 ed [2] 4c ea [2] 50 c5 }

  condition:
    any of them
}