rule TTP_XOR_QUAD_CurrentVersionRun_d699 {
  strings:
    $key_d699 = { 85 f6 [2] a1 f8 [2] 8a d4 [2] a4 f6 [2] b0 ed [2] bf f7 [2] a1 ea [2] a3 eb [2] b8 ed [2] a4 ea [2] b8 c5 }

  condition:
    any of them
}