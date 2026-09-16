rule TTP_XOR_QUAD_CurrentVersionRun_e785 {
  strings:
    $key_e785 = { b4 ea [2] 90 e4 [2] bb c8 [2] 95 ea [2] 81 f1 [2] 8e eb [2] 90 f6 [2] 92 f7 [2] 89 f1 [2] 95 f6 [2] 89 d9 }

  condition:
    any of them
}