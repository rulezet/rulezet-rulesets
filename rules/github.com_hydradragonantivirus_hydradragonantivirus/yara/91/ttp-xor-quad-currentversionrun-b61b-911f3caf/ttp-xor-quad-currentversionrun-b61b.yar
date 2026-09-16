rule TTP_XOR_QUAD_CurrentVersionRun_b61b {
  strings:
    $key_b61b = { e5 74 [2] c1 7a [2] ea 56 [2] c4 74 [2] d0 6f [2] df 75 [2] c1 68 [2] c3 69 [2] d8 6f [2] c4 68 [2] d8 47 }

  condition:
    any of them
}