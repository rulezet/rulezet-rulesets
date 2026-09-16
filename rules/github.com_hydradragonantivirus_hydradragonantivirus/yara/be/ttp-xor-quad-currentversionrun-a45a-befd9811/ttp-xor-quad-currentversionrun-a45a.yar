rule TTP_XOR_QUAD_CurrentVersionRun_a45a {
  strings:
    $key_a45a = { f7 35 [2] d3 3b [2] f8 17 [2] d6 35 [2] c2 2e [2] cd 34 [2] d3 29 [2] d1 28 [2] ca 2e [2] d6 29 [2] ca 06 }

  condition:
    any of them
}