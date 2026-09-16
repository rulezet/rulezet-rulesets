rule TTP_XOR_QUAD_CurrentVersionRun_abb2 {
  strings:
    $key_abb2 = { f8 dd [2] dc d3 [2] f7 ff [2] d9 dd [2] cd c6 [2] c2 dc [2] dc c1 [2] de c0 [2] c5 c6 [2] d9 c1 [2] c5 ee }

  condition:
    any of them
}