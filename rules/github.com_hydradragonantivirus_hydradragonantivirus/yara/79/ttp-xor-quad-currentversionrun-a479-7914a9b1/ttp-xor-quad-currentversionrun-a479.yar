rule TTP_XOR_QUAD_CurrentVersionRun_a479 {
  strings:
    $key_a479 = { f7 16 [2] d3 18 [2] f8 34 [2] d6 16 [2] c2 0d [2] cd 17 [2] d3 0a [2] d1 0b [2] ca 0d [2] d6 0a [2] ca 25 }

  condition:
    any of them
}