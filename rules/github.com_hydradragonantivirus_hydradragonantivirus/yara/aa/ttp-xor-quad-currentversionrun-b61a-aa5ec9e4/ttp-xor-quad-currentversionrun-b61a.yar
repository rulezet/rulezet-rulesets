rule TTP_XOR_QUAD_CurrentVersionRun_b61a {
  strings:
    $key_b61a = { e5 75 [2] c1 7b [2] ea 57 [2] c4 75 [2] d0 6e [2] df 74 [2] c1 69 [2] c3 68 [2] d8 6e [2] c4 69 [2] d8 46 }

  condition:
    any of them
}