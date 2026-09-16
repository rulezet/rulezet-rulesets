rule TTP_XOR_QUAD_CurrentVersionRun_a458 {
  strings:
    $key_a458 = { f7 37 [2] d3 39 [2] f8 15 [2] d6 37 [2] c2 2c [2] cd 36 [2] d3 2b [2] d1 2a [2] ca 2c [2] d6 2b [2] ca 04 }

  condition:
    any of them
}