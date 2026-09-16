rule TTP_XOR_QUAD_CurrentVersionRun_b6e4 {
  strings:
    $key_b6e4 = { e5 8b [2] c1 85 [2] ea a9 [2] c4 8b [2] d0 90 [2] df 8a [2] c1 97 [2] c3 96 [2] d8 90 [2] c4 97 [2] d8 b8 }

  condition:
    any of them
}