rule TTP_XOR_QUAD_CurrentVersionRun_e398 {
  strings:
    $key_e398 = { b0 f7 [2] 94 f9 [2] bf d5 [2] 91 f7 [2] 85 ec [2] 8a f6 [2] 94 eb [2] 96 ea [2] 8d ec [2] 91 eb [2] 8d c4 }

  condition:
    any of them
}