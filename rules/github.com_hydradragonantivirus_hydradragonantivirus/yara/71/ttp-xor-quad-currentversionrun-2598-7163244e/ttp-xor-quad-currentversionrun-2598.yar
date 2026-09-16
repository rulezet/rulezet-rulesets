rule TTP_XOR_QUAD_CurrentVersionRun_2598 {
  strings:
    $key_2598 = { 76 f7 [2] 52 f9 [2] 79 d5 [2] 57 f7 [2] 43 ec [2] 4c f6 [2] 52 eb [2] 50 ea [2] 4b ec [2] 57 eb [2] 4b c4 }

  condition:
    any of them
}