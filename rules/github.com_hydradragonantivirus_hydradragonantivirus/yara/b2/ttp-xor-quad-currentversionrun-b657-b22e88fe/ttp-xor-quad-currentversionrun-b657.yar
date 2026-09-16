rule TTP_XOR_QUAD_CurrentVersionRun_b657 {
  strings:
    $key_b657 = { e5 38 [2] c1 36 [2] ea 1a [2] c4 38 [2] d0 23 [2] df 39 [2] c1 24 [2] c3 25 [2] d8 23 [2] c4 24 [2] d8 0b }

  condition:
    any of them
}