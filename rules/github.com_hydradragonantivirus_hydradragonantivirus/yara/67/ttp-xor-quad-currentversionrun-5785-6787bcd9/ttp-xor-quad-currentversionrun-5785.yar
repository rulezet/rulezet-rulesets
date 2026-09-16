rule TTP_XOR_QUAD_CurrentVersionRun_5785 {
  strings:
    $key_5785 = { 04 ea [2] 20 e4 [2] 0b c8 [2] 25 ea [2] 31 f1 [2] 3e eb [2] 20 f6 [2] 22 f7 [2] 39 f1 [2] 25 f6 [2] 39 d9 }

  condition:
    any of them
}