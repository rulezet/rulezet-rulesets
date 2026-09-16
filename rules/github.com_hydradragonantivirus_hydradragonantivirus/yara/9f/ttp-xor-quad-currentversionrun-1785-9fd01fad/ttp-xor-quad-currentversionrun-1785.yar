rule TTP_XOR_QUAD_CurrentVersionRun_1785 {
  strings:
    $key_1785 = { 44 ea [2] 60 e4 [2] 4b c8 [2] 65 ea [2] 71 f1 [2] 7e eb [2] 60 f6 [2] 62 f7 [2] 79 f1 [2] 65 f6 [2] 79 d9 }

  condition:
    any of them
}