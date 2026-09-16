rule TTP_XOR_QUAD_CurrentVersionRun_6785 {
  strings:
    $key_6785 = { 34 ea [2] 10 e4 [2] 3b c8 [2] 15 ea [2] 01 f1 [2] 0e eb [2] 10 f6 [2] 12 f7 [2] 09 f1 [2] 15 f6 [2] 09 d9 }

  condition:
    any of them
}