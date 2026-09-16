rule TTP_XOR_QUAD_CurrentVersionRun_3199 {
  strings:
    $key_3199 = { 62 f6 [2] 46 f8 [2] 6d d4 [2] 43 f6 [2] 57 ed [2] 58 f7 [2] 46 ea [2] 44 eb [2] 5f ed [2] 43 ea [2] 5f c5 }

  condition:
    any of them
}