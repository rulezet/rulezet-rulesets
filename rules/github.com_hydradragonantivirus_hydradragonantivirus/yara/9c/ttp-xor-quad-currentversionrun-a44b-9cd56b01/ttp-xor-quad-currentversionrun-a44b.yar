rule TTP_XOR_QUAD_CurrentVersionRun_a44b {
  strings:
    $key_a44b = { f7 24 [2] d3 2a [2] f8 06 [2] d6 24 [2] c2 3f [2] cd 25 [2] d3 38 [2] d1 39 [2] ca 3f [2] d6 38 [2] ca 17 }

  condition:
    any of them
}