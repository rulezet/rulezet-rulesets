rule TTP_XOR_QUAD_CurrentVersionRun_a473 {
  strings:
    $key_a473 = { f7 1c [2] d3 12 [2] f8 3e [2] d6 1c [2] c2 07 [2] cd 1d [2] d3 00 [2] d1 01 [2] ca 07 [2] d6 00 [2] ca 2f }

  condition:
    any of them
}