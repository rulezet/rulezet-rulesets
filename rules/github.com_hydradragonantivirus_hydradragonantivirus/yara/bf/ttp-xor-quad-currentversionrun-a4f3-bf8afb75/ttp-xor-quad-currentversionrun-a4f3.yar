rule TTP_XOR_QUAD_CurrentVersionRun_a4f3 {
  strings:
    $key_a4f3 = { f7 9c [2] d3 92 [2] f8 be [2] d6 9c [2] c2 87 [2] cd 9d [2] d3 80 [2] d1 81 [2] ca 87 [2] d6 80 [2] ca af }

  condition:
    any of them
}