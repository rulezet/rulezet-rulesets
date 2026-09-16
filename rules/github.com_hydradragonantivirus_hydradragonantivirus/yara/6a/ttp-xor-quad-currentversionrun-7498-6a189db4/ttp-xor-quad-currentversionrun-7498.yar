rule TTP_XOR_QUAD_CurrentVersionRun_7498 {
  strings:
    $key_7498 = { 27 f7 [2] 03 f9 [2] 28 d5 [2] 06 f7 [2] 12 ec [2] 1d f6 [2] 03 eb [2] 01 ea [2] 1a ec [2] 06 eb [2] 1a c4 }

  condition:
    any of them
}