rule TTP_XOR_QUAD_CurrentVersionRun_b10e {
  strings:
    $key_b10e = { e2 61 [2] c6 6f [2] ed 43 [2] c3 61 [2] d7 7a [2] d8 60 [2] c6 7d [2] c4 7c [2] df 7a [2] c3 7d [2] df 52 }

  condition:
    any of them
}