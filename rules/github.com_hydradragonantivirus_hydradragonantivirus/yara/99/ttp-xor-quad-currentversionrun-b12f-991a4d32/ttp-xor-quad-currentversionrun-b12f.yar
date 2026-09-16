rule TTP_XOR_QUAD_CurrentVersionRun_b12f {
  strings:
    $key_b12f = { e2 40 [2] c6 4e [2] ed 62 [2] c3 40 [2] d7 5b [2] d8 41 [2] c6 5c [2] c4 5d [2] df 5b [2] c3 5c [2] df 73 }

  condition:
    any of them
}