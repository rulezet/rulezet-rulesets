rule TTP_XOR_QUAD_CurrentVersionRun_a4e1 {
  strings:
    $key_a4e1 = { f7 8e [2] d3 80 [2] f8 ac [2] d6 8e [2] c2 95 [2] cd 8f [2] d3 92 [2] d1 93 [2] ca 95 [2] d6 92 [2] ca bd }

  condition:
    any of them
}