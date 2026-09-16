rule TTP_XOR_QUAD_CurrentVersionRun_f785 {
  strings:
    $key_f785 = { a4 ea [2] 80 e4 [2] ab c8 [2] 85 ea [2] 91 f1 [2] 9e eb [2] 80 f6 [2] 82 f7 [2] 99 f1 [2] 85 f6 [2] 99 d9 }

  condition:
    any of them
}