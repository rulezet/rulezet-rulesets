rule TTP_XOR_QUAD_CurrentVersionRun_3499 {
  strings:
    $key_3499 = { 67 f6 [2] 43 f8 [2] 68 d4 [2] 46 f6 [2] 52 ed [2] 5d f7 [2] 43 ea [2] 41 eb [2] 5a ed [2] 46 ea [2] 5a c5 }

  condition:
    any of them
}