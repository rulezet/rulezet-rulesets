rule TTP_XOR_QUAD_CurrentVersionRun_a422 {
  strings:
    $key_a422 = { f7 4d [2] d3 43 [2] f8 6f [2] d6 4d [2] c2 56 [2] cd 4c [2] d3 51 [2] d1 50 [2] ca 56 [2] d6 51 [2] ca 7e }

  condition:
    any of them
}