rule TTP_XOR_QUAD_CurrentVersionRun_4798 {
  strings:
    $key_4798 = { 14 f7 [2] 30 f9 [2] 1b d5 [2] 35 f7 [2] 21 ec [2] 2e f6 [2] 30 eb [2] 32 ea [2] 29 ec [2] 35 eb [2] 29 c4 }

  condition:
    any of them
}