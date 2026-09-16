rule TTP_XOR_QUAD_CurrentVersionRun_a406 {
  strings:
    $key_a406 = { f7 69 [2] d3 67 [2] f8 4b [2] d6 69 [2] c2 72 [2] cd 68 [2] d3 75 [2] d1 74 [2] ca 72 [2] d6 75 [2] ca 5a }

  condition:
    any of them
}