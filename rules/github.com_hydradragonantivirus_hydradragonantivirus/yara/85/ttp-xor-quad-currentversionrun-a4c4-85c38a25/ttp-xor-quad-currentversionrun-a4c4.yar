rule TTP_XOR_QUAD_CurrentVersionRun_a4c4 {
  strings:
    $key_a4c4 = { f7 ab [2] d3 a5 [2] f8 89 [2] d6 ab [2] c2 b0 [2] cd aa [2] d3 b7 [2] d1 b6 [2] ca b0 [2] d6 b7 [2] ca 98 }

  condition:
    any of them
}