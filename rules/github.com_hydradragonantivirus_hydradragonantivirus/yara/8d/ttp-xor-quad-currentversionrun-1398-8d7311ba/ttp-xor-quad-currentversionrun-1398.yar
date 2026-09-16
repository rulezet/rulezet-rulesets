rule TTP_XOR_QUAD_CurrentVersionRun_1398 {
  strings:
    $key_1398 = { 40 f7 [2] 64 f9 [2] 4f d5 [2] 61 f7 [2] 75 ec [2] 7a f6 [2] 64 eb [2] 66 ea [2] 7d ec [2] 61 eb [2] 7d c4 }

  condition:
    any of them
}