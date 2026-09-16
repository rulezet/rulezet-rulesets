rule TTP_XOR_QUAD_CurrentVersionRun_a425 {
  strings:
    $key_a425 = { f7 4a [2] d3 44 [2] f8 68 [2] d6 4a [2] c2 51 [2] cd 4b [2] d3 56 [2] d1 57 [2] ca 51 [2] d6 56 [2] ca 79 }

  condition:
    any of them
}