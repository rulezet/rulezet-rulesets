rule TTP_XOR_QUAD_CurrentVersionRun_d785 {
  strings:
    $key_d785 = { 84 ea [2] a0 e4 [2] 8b c8 [2] a5 ea [2] b1 f1 [2] be eb [2] a0 f6 [2] a2 f7 [2] b9 f1 [2] a5 f6 [2] b9 d9 }

  condition:
    any of them
}