rule TTP_XOR_QUAD_CurrentVersionRun_2785 {
  strings:
    $key_2785 = { 74 ea [2] 50 e4 [2] 7b c8 [2] 55 ea [2] 41 f1 [2] 4e eb [2] 50 f6 [2] 52 f7 [2] 49 f1 [2] 55 f6 [2] 49 d9 }

  condition:
    any of them
}