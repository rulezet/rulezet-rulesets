rule TTP_XOR_QUAD_CurrentVersionRun_b604 {
  strings:
    $key_b604 = { e5 6b [2] c1 65 [2] ea 49 [2] c4 6b [2] d0 70 [2] df 6a [2] c1 77 [2] c3 76 [2] d8 70 [2] c4 77 [2] d8 58 }

  condition:
    any of them
}