rule TTP_XOR_QUAD_CurrentVersionRun_a41b {
  strings:
    $key_a41b = { f7 74 [2] d3 7a [2] f8 56 [2] d6 74 [2] c2 6f [2] cd 75 [2] d3 68 [2] d1 69 [2] ca 6f [2] d6 68 [2] ca 47 }

  condition:
    any of them
}