rule TTP_XOR_QUAD_CurrentVersionRun_b499 {
  strings:
    $key_b499 = { e7 f6 [2] c3 f8 [2] e8 d4 [2] c6 f6 [2] d2 ed [2] dd f7 [2] c3 ea [2] c1 eb [2] da ed [2] c6 ea [2] da c5 }

  condition:
    any of them
}