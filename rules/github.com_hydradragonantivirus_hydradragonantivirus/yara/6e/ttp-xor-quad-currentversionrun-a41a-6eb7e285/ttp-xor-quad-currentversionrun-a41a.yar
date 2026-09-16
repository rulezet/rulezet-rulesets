rule TTP_XOR_QUAD_CurrentVersionRun_a41a {
  strings:
    $key_a41a = { f7 75 [2] d3 7b [2] f8 57 [2] d6 75 [2] c2 6e [2] cd 74 [2] d3 69 [2] d1 68 [2] ca 6e [2] d6 69 [2] ca 46 }

  condition:
    any of them
}