rule TTP_XOR_QUAD_CurrentVersionRun_a4ef {
  strings:
    $key_a4ef = { f7 80 [2] d3 8e [2] f8 a2 [2] d6 80 [2] c2 9b [2] cd 81 [2] d3 9c [2] d1 9d [2] ca 9b [2] d6 9c [2] ca b3 }

  condition:
    any of them
}