rule TTP_XOR_QUAD_CurrentVersionRun_4785 {
  strings:
    $key_4785 = { 14 ea [2] 30 e4 [2] 1b c8 [2] 35 ea [2] 21 f1 [2] 2e eb [2] 30 f6 [2] 32 f7 [2] 29 f1 [2] 35 f6 [2] 29 d9 }

  condition:
    any of them
}