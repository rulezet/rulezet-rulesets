rule TTP_XOR_QUAD_CurrentVersionRun_b6f9 {
  strings:
    $key_b6f9 = { e5 96 [2] c1 98 [2] ea b4 [2] c4 96 [2] d0 8d [2] df 97 [2] c1 8a [2] c3 8b [2] d8 8d [2] c4 8a [2] d8 a5 }

  condition:
    any of them
}