rule TTP_XOR_QUAD_CurrentVersionRun_a456 {
  strings:
    $key_a456 = { f7 39 [2] d3 37 [2] f8 1b [2] d6 39 [2] c2 22 [2] cd 38 [2] d3 25 [2] d1 24 [2] ca 22 [2] d6 25 [2] ca 0a }

  condition:
    any of them
}