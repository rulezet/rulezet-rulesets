rule TTP_XOR_QUAD_CurrentVersionRun_b684 {
  strings:
    $key_b684 = { e5 eb [2] c1 e5 [2] ea c9 [2] c4 eb [2] d0 f0 [2] df ea [2] c1 f7 [2] c3 f6 [2] d8 f0 [2] c4 f7 [2] d8 d8 }

  condition:
    any of them
}