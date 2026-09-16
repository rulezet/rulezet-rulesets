rule TTP_XOR_QUAD_CurrentVersionRun_a445 {
  strings:
    $key_a445 = { f7 2a [2] d3 24 [2] f8 08 [2] d6 2a [2] c2 31 [2] cd 2b [2] d3 36 [2] d1 37 [2] ca 31 [2] d6 36 [2] ca 19 }

  condition:
    any of them
}