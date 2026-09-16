rule TTP_XOR_QUAD_CurrentVersionRun_5399 {
  strings:
    $key_5399 = { 00 f6 [2] 24 f8 [2] 0f d4 [2] 21 f6 [2] 35 ed [2] 3a f7 [2] 24 ea [2] 26 eb [2] 3d ed [2] 21 ea [2] 3d c5 }

  condition:
    any of them
}