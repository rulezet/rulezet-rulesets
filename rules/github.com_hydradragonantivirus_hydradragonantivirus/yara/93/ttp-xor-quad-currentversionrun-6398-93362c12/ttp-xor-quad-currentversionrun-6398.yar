rule TTP_XOR_QUAD_CurrentVersionRun_6398 {
  strings:
    $key_6398 = { 30 f7 [2] 14 f9 [2] 3f d5 [2] 11 f7 [2] 05 ec [2] 0a f6 [2] 14 eb [2] 16 ea [2] 0d ec [2] 11 eb [2] 0d c4 }

  condition:
    any of them
}