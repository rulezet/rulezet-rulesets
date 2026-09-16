rule TTP_XOR_QUAD_CurrentVersionRun_a434 {
  strings:
    $key_a434 = { f7 5b [2] d3 55 [2] f8 79 [2] d6 5b [2] c2 40 [2] cd 5a [2] d3 47 [2] d1 46 [2] ca 40 [2] d6 47 [2] ca 68 }

  condition:
    any of them
}