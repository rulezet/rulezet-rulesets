rule TTP_XOR_QUAD_CurrentVersionRun_4398 {
  strings:
    $key_4398 = { 10 f7 [2] 34 f9 [2] 1f d5 [2] 31 f7 [2] 25 ec [2] 2a f6 [2] 34 eb [2] 36 ea [2] 2d ec [2] 31 eb [2] 2d c4 }

  condition:
    any of them
}