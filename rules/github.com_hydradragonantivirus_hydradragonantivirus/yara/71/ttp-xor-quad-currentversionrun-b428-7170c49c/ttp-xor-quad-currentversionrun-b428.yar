rule TTP_XOR_QUAD_CurrentVersionRun_b428 {
  strings:
    $key_b428 = { e7 47 [2] c3 49 [2] e8 65 [2] c6 47 [2] d2 5c [2] dd 46 [2] c3 5b [2] c1 5a [2] da 5c [2] c6 5b [2] da 74 }

  condition:
    any of them
}