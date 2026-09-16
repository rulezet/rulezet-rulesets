rule TTP_XOR_QUAD_CurrentVersionRun_2398 {
  strings:
    $key_2398 = { 70 f7 [2] 54 f9 [2] 7f d5 [2] 51 f7 [2] 45 ec [2] 4a f6 [2] 54 eb [2] 56 ea [2] 4d ec [2] 51 eb [2] 4d c4 }

  condition:
    any of them
}