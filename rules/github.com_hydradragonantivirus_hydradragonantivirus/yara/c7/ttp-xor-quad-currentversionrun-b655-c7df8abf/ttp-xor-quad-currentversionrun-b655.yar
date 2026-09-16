rule TTP_XOR_QUAD_CurrentVersionRun_b655 {
  strings:
    $key_b655 = { e5 3a [2] c1 34 [2] ea 18 [2] c4 3a [2] d0 21 [2] df 3b [2] c1 26 [2] c3 27 [2] d8 21 [2] c4 26 [2] d8 09 }

  condition:
    any of them
}