rule TTP_XOR_QUAD_CurrentVersionRun_a439 {
  strings:
    $key_a439 = { f7 56 [2] d3 58 [2] f8 74 [2] d6 56 [2] c2 4d [2] cd 57 [2] d3 4a [2] d1 4b [2] ca 4d [2] d6 4a [2] ca 65 }

  condition:
    any of them
}