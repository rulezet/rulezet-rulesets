rule TTP_XOR_QUAD_CurrentVersionRun_b6f8 {
  strings:
    $key_b6f8 = { e5 97 [2] c1 99 [2] ea b5 [2] c4 97 [2] d0 8c [2] df 96 [2] c1 8b [2] c3 8a [2] d8 8c [2] c4 8b [2] d8 a4 }

  condition:
    any of them
}