rule TTP_XOR_QUAD_CurrentVersionRun_a4a2 {
  strings:
    $key_a4a2 = { f7 cd [2] d3 c3 [2] f8 ef [2] d6 cd [2] c2 d6 [2] cd cc [2] d3 d1 [2] d1 d0 [2] ca d6 [2] d6 d1 [2] ca fe }

  condition:
    any of them
}