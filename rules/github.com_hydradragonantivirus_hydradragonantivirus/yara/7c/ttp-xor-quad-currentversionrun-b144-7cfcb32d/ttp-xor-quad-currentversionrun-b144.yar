rule TTP_XOR_QUAD_CurrentVersionRun_b144 {
  strings:
    $key_b144 = { e2 2b [2] c6 25 [2] ed 09 [2] c3 2b [2] d7 30 [2] d8 2a [2] c6 37 [2] c4 36 [2] df 30 [2] c3 37 [2] df 18 }

  condition:
    any of them
}