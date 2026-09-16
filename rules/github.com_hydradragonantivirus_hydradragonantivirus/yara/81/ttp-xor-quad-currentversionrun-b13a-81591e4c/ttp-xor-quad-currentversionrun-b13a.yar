rule TTP_XOR_QUAD_CurrentVersionRun_b13a {
  strings:
    $key_b13a = { e2 55 [2] c6 5b [2] ed 77 [2] c3 55 [2] d7 4e [2] d8 54 [2] c6 49 [2] c4 48 [2] df 4e [2] c3 49 [2] df 66 }

  condition:
    any of them
}