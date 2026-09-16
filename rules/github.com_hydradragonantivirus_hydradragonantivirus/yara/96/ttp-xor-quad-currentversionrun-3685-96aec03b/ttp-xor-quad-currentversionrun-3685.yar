rule TTP_XOR_QUAD_CurrentVersionRun_3685 {
  strings:
    $key_3685 = { 65 ea [2] 41 e4 [2] 6a c8 [2] 44 ea [2] 50 f1 [2] 5f eb [2] 41 f6 [2] 43 f7 [2] 58 f1 [2] 44 f6 [2] 58 d9 }

  condition:
    any of them
}