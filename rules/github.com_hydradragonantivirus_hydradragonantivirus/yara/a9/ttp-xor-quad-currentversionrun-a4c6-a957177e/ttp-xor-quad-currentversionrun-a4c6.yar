rule TTP_XOR_QUAD_CurrentVersionRun_a4c6 {
  strings:
    $key_a4c6 = { f7 a9 [2] d3 a7 [2] f8 8b [2] d6 a9 [2] c2 b2 [2] cd a8 [2] d3 b5 [2] d1 b4 [2] ca b2 [2] d6 b5 [2] ca 9a }

  condition:
    any of them
}