rule TTP_XOR_QUAD_CurrentVersionRun_e784 {
  strings:
    $key_e784 = { b4 eb [2] 90 e5 [2] bb c9 [2] 95 eb [2] 81 f0 [2] 8e ea [2] 90 f7 [2] 92 f6 [2] 89 f0 [2] 95 f7 [2] 89 d8 }

  condition:
    any of them
}