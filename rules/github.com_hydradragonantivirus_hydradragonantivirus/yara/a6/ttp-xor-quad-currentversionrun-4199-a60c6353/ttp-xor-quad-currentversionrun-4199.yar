rule TTP_XOR_QUAD_CurrentVersionRun_4199 {
  strings:
    $key_4199 = { 12 f6 [2] 36 f8 [2] 1d d4 [2] 33 f6 [2] 27 ed [2] 28 f7 [2] 36 ea [2] 34 eb [2] 2f ed [2] 33 ea [2] 2f c5 }

  condition:
    any of them
}