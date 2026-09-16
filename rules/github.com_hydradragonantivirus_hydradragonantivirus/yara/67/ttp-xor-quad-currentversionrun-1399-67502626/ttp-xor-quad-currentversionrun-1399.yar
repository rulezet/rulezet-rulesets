rule TTP_XOR_QUAD_CurrentVersionRun_1399 {
  strings:
    $key_1399 = { 40 f6 [2] 64 f8 [2] 4f d4 [2] 61 f6 [2] 75 ed [2] 7a f7 [2] 64 ea [2] 66 eb [2] 7d ed [2] 61 ea [2] 7d c5 }

  condition:
    any of them
}