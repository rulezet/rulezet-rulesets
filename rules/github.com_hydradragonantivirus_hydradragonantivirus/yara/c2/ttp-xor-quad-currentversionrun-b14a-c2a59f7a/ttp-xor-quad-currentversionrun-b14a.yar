rule TTP_XOR_QUAD_CurrentVersionRun_b14a {
  strings:
    $key_b14a = { e2 25 [2] c6 2b [2] ed 07 [2] c3 25 [2] d7 3e [2] d8 24 [2] c6 39 [2] c4 38 [2] df 3e [2] c3 39 [2] df 16 }

  condition:
    any of them
}