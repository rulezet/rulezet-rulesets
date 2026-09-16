rule TTP_XOR_QUAD_CurrentVersionRun_b12d {
  strings:
    $key_b12d = { e2 42 [2] c6 4c [2] ed 60 [2] c3 42 [2] d7 59 [2] d8 43 [2] c6 5e [2] c4 5f [2] df 59 [2] c3 5e [2] df 71 }

  condition:
    any of them
}