rule TTP_XOR_QUAD_CurrentVersionRun_4384 {
  strings:
    $key_4384 = { 10 eb [2] 34 e5 [2] 1f c9 [2] 31 eb [2] 25 f0 [2] 2a ea [2] 34 f7 [2] 36 f6 [2] 2d f0 [2] 31 f7 [2] 2d d8 }

  condition:
    any of them
}