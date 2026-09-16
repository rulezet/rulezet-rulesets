rule TTP_XOR_QUAD_CurrentVersionRun_2685 {
  strings:
    $key_2685 = { 75 ea [2] 51 e4 [2] 7a c8 [2] 54 ea [2] 40 f1 [2] 4f eb [2] 51 f6 [2] 53 f7 [2] 48 f1 [2] 54 f6 [2] 48 d9 }

  condition:
    any of them
}