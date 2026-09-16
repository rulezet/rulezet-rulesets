rule TTP_XOR_QUAD_CurrentVersionRun_7598 {
  strings:
    $key_7598 = { 26 f7 [2] 02 f9 [2] 29 d5 [2] 07 f7 [2] 13 ec [2] 1c f6 [2] 02 eb [2] 00 ea [2] 1b ec [2] 07 eb [2] 1b c4 }

  condition:
    any of them
}