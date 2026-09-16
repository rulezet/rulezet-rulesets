rule TTP_XOR_QUAD_CurrentVersionRun_a468 {
  strings:
    $key_a468 = { f7 07 [2] d3 09 [2] f8 25 [2] d6 07 [2] c2 1c [2] cd 06 [2] d3 1b [2] d1 1a [2] ca 1c [2] d6 1b [2] ca 34 }

  condition:
    any of them
}