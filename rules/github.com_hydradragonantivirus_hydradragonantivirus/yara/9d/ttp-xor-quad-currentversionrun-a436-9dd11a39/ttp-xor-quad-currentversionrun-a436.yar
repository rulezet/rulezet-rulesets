rule TTP_XOR_QUAD_CurrentVersionRun_a436 {
  strings:
    $key_a436 = { f7 59 [2] d3 57 [2] f8 7b [2] d6 59 [2] c2 42 [2] cd 58 [2] d3 45 [2] d1 44 [2] ca 42 [2] d6 45 [2] ca 6a }

  condition:
    any of them
}