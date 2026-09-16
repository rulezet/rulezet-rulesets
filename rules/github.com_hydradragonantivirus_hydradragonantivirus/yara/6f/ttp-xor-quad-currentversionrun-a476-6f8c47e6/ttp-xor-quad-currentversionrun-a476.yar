rule TTP_XOR_QUAD_CurrentVersionRun_a476 {
  strings:
    $key_a476 = { f7 19 [2] d3 17 [2] f8 3b [2] d6 19 [2] c2 02 [2] cd 18 [2] d3 05 [2] d1 04 [2] ca 02 [2] d6 05 [2] ca 2a }

  condition:
    any of them
}