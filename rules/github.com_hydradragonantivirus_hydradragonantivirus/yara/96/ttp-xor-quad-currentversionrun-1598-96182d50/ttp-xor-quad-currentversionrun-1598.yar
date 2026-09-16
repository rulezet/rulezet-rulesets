rule TTP_XOR_QUAD_CurrentVersionRun_1598 {
  strings:
    $key_1598 = { 46 f7 [2] 62 f9 [2] 49 d5 [2] 67 f7 [2] 73 ec [2] 7c f6 [2] 62 eb [2] 60 ea [2] 7b ec [2] 67 eb [2] 7b c4 }

  condition:
    any of them
}