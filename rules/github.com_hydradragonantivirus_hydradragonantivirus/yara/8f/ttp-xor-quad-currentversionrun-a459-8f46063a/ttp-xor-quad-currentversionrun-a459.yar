rule TTP_XOR_QUAD_CurrentVersionRun_a459 {
  strings:
    $key_a459 = { f7 36 [2] d3 38 [2] f8 14 [2] d6 36 [2] c2 2d [2] cd 37 [2] d3 2a [2] d1 2b [2] ca 2d [2] d6 2a [2] ca 05 }

  condition:
    any of them
}