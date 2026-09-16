rule TTP_XOR_QUAD_CurrentVersionRun_d685 {
  strings:
    $key_d685 = { 85 ea [2] a1 e4 [2] 8a c8 [2] a4 ea [2] b0 f1 [2] bf eb [2] a1 f6 [2] a3 f7 [2] b8 f1 [2] a4 f6 [2] b8 d9 }

  condition:
    any of them
}