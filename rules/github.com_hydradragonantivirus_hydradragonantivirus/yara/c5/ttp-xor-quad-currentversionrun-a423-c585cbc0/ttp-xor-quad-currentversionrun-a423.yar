rule TTP_XOR_QUAD_CurrentVersionRun_a423 {
  strings:
    $key_a423 = { f7 4c [2] d3 42 [2] f8 6e [2] d6 4c [2] c2 57 [2] cd 4d [2] d3 50 [2] d1 51 [2] ca 57 [2] d6 50 [2] ca 7f }

  condition:
    any of them
}