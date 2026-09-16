rule TTP_XOR_QUAD_CurrentVersionRun_db99 {
  strings:
    $key_db99 = { 88 f6 [2] ac f8 [2] 87 d4 [2] a9 f6 [2] bd ed [2] b2 f7 [2] ac ea [2] ae eb [2] b5 ed [2] a9 ea [2] b5 c5 }

  condition:
    any of them
}