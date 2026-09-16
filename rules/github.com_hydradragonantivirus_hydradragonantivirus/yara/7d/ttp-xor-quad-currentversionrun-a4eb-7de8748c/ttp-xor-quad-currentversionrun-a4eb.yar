rule TTP_XOR_QUAD_CurrentVersionRun_a4eb {
  strings:
    $key_a4eb = { f7 84 [2] d3 8a [2] f8 a6 [2] d6 84 [2] c2 9f [2] cd 85 [2] d3 98 [2] d1 99 [2] ca 9f [2] d6 98 [2] ca b7 }

  condition:
    any of them
}