rule TTP_XOR_QUAD_CurrentVersionRun_b13e {
  strings:
    $key_b13e = { e2 51 [2] c6 5f [2] ed 73 [2] c3 51 [2] d7 4a [2] d8 50 [2] c6 4d [2] c4 4c [2] df 4a [2] c3 4d [2] df 62 }

  condition:
    any of them
}