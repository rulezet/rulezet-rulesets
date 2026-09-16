rule TTP_XOR_QUAD_CurrentVersionRun_b6fa {
  strings:
    $key_b6fa = { e5 95 [2] c1 9b [2] ea b7 [2] c4 95 [2] d0 8e [2] df 94 [2] c1 89 [2] c3 88 [2] d8 8e [2] c4 89 [2] d8 a6 }

  condition:
    any of them
}