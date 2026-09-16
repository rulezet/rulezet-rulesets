rule TTP_XOR_QUAD_CurrentVersionRun_a4f7 {
  strings:
    $key_a4f7 = { f7 98 [2] d3 96 [2] f8 ba [2] d6 98 [2] c2 83 [2] cd 99 [2] d3 84 [2] d1 85 [2] ca 83 [2] d6 84 [2] ca ab }

  condition:
    any of them
}