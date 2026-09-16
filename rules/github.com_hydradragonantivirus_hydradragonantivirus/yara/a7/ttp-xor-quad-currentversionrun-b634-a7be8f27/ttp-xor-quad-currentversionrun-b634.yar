rule TTP_XOR_QUAD_CurrentVersionRun_b634 {
  strings:
    $key_b634 = { e5 5b [2] c1 55 [2] ea 79 [2] c4 5b [2] d0 40 [2] df 5a [2] c1 47 [2] c3 46 [2] d8 40 [2] c4 47 [2] d8 68 }

  condition:
    any of them
}