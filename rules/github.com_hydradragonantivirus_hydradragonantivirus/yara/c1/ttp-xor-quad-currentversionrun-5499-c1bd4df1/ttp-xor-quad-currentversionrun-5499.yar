rule TTP_XOR_QUAD_CurrentVersionRun_5499 {
  strings:
    $key_5499 = { 07 f6 [2] 23 f8 [2] 08 d4 [2] 26 f6 [2] 32 ed [2] 3d f7 [2] 23 ea [2] 21 eb [2] 3a ed [2] 26 ea [2] 3a c5 }

  condition:
    any of them
}