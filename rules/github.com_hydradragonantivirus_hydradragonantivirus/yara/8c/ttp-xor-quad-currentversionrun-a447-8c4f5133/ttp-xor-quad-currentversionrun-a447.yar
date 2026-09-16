rule TTP_XOR_QUAD_CurrentVersionRun_a447 {
  strings:
    $key_a447 = { f7 28 [2] d3 26 [2] f8 0a [2] d6 28 [2] c2 33 [2] cd 29 [2] d3 34 [2] d1 35 [2] ca 33 [2] d6 34 [2] ca 1b }

  condition:
    any of them
}