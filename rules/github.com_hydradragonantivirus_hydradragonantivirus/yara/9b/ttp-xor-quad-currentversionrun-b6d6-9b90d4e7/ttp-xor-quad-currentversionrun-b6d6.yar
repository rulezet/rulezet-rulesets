rule TTP_XOR_QUAD_CurrentVersionRun_b6d6 {
  strings:
    $key_b6d6 = { e5 b9 [2] c1 b7 [2] ea 9b [2] c4 b9 [2] d0 a2 [2] df b8 [2] c1 a5 [2] c3 a4 [2] d8 a2 [2] c4 a5 [2] d8 8a }

  condition:
    any of them
}