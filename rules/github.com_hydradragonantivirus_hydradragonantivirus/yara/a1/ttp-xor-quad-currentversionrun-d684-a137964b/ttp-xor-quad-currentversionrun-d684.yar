rule TTP_XOR_QUAD_CurrentVersionRun_d684 {
  strings:
    $key_d684 = { 85 eb [2] a1 e5 [2] 8a c9 [2] a4 eb [2] b0 f0 [2] bf ea [2] a1 f7 [2] a3 f6 [2] b8 f0 [2] a4 f7 [2] b8 d8 }

  condition:
    any of them
}