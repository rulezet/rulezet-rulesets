rule TTP_XOR_QUAD_CurrentVersionRun_a4e6 {
  strings:
    $key_a4e6 = { f7 89 [2] d3 87 [2] f8 ab [2] d6 89 [2] c2 92 [2] cd 88 [2] d3 95 [2] d1 94 [2] ca 92 [2] d6 95 [2] ca ba }

  condition:
    any of them
}