rule TTP_XOR_QUAD_CurrentVersionRun_a4d2 {
  strings:
    $key_a4d2 = { f7 bd [2] d3 b3 [2] f8 9f [2] d6 bd [2] c2 a6 [2] cd bc [2] d3 a1 [2] d1 a0 [2] ca a6 [2] d6 a1 [2] ca 8e }

  condition:
    any of them
}