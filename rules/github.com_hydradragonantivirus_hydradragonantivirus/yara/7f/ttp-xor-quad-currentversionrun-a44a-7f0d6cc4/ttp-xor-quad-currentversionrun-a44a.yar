rule TTP_XOR_QUAD_CurrentVersionRun_a44a {
  strings:
    $key_a44a = { f7 25 [2] d3 2b [2] f8 07 [2] d6 25 [2] c2 3e [2] cd 24 [2] d3 39 [2] d1 38 [2] ca 3e [2] d6 39 [2] ca 16 }

  condition:
    any of them
}