rule TTP_XOR_QUAD_CurrentVersionRun_a475 {
  strings:
    $key_a475 = { f7 1a [2] d3 14 [2] f8 38 [2] d6 1a [2] c2 01 [2] cd 1b [2] d3 06 [2] d1 07 [2] ca 01 [2] d6 06 [2] ca 29 }

  condition:
    any of them
}