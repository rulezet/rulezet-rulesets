rule TTP_XOR_QUAD_CurrentVersionRun_4399 {
  strings:
    $key_4399 = { 10 f6 [2] 34 f8 [2] 1f d4 [2] 31 f6 [2] 25 ed [2] 2a f7 [2] 34 ea [2] 36 eb [2] 2d ed [2] 31 ea [2] 2d c5 }

  condition:
    any of them
}