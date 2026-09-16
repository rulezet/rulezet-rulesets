rule TTP_XOR_QUAD_CurrentVersionRun_a461 {
  strings:
    $key_a461 = { f7 0e [2] d3 00 [2] f8 2c [2] d6 0e [2] c2 15 [2] cd 0f [2] d3 12 [2] d1 13 [2] ca 15 [2] d6 12 [2] ca 3d }

  condition:
    any of them
}