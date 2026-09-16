rule TTP_XOR_QUAD_CurrentVersionRun_5685 {
  strings:
    $key_5685 = { 05 ea [2] 21 e4 [2] 0a c8 [2] 24 ea [2] 30 f1 [2] 3f eb [2] 21 f6 [2] 23 f7 [2] 38 f1 [2] 24 f6 [2] 38 d9 }

  condition:
    any of them
}