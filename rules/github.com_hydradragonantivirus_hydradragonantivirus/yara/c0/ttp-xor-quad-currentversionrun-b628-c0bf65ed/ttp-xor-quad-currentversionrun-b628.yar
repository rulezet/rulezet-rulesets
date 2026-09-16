rule TTP_XOR_QUAD_CurrentVersionRun_b628 {
  strings:
    $key_b628 = { e5 47 [2] c1 49 [2] ea 65 [2] c4 47 [2] d0 5c [2] df 46 [2] c1 5b [2] c3 5a [2] d8 5c [2] c4 5b [2] d8 74 }

  condition:
    any of them
}