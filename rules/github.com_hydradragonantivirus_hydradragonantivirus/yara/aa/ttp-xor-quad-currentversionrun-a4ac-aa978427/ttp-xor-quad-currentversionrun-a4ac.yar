rule TTP_XOR_QUAD_CurrentVersionRun_a4ac {
  strings:
    $key_a4ac = { f7 c3 [2] d3 cd [2] f8 e1 [2] d6 c3 [2] c2 d8 [2] cd c2 [2] d3 df [2] d1 de [2] ca d8 [2] d6 df [2] ca f0 }

  condition:
    any of them
}