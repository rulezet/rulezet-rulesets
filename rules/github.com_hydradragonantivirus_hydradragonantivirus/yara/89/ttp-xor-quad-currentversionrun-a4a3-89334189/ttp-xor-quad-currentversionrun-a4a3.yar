rule TTP_XOR_QUAD_CurrentVersionRun_a4a3 {
  strings:
    $key_a4a3 = { f7 cc [2] d3 c2 [2] f8 ee [2] d6 cc [2] c2 d7 [2] cd cd [2] d3 d0 [2] d1 d1 [2] ca d7 [2] d6 d0 [2] ca ff }

  condition:
    any of them
}