rule TTP_XOR_QUAD_CurrentVersionRun_a409 {
  strings:
    $key_a409 = { f7 66 [2] d3 68 [2] f8 44 [2] d6 66 [2] c2 7d [2] cd 67 [2] d3 7a [2] d1 7b [2] ca 7d [2] d6 7a [2] ca 55 }

  condition:
    any of them
}