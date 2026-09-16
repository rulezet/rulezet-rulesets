rule TTP_XOR_QUAD_CurrentVersionRun_f398 {
  strings:
    $key_f398 = { a0 f7 [2] 84 f9 [2] af d5 [2] 81 f7 [2] 95 ec [2] 9a f6 [2] 84 eb [2] 86 ea [2] 9d ec [2] 81 eb [2] 9d c4 }

  condition:
    any of them
}