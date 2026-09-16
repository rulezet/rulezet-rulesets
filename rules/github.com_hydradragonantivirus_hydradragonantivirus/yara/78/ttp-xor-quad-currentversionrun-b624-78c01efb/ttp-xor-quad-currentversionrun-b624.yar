rule TTP_XOR_QUAD_CurrentVersionRun_b624 {
  strings:
    $key_b624 = { e5 4b [2] c1 45 [2] ea 69 [2] c4 4b [2] d0 50 [2] df 4a [2] c1 57 [2] c3 56 [2] d8 50 [2] c4 57 [2] d8 78 }

  condition:
    any of them
}