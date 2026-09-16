rule TTP_XOR_QUAD_CurrentVersionRun_a4d8 {
  strings:
    $key_a4d8 = { f7 b7 [2] d3 b9 [2] f8 95 [2] d6 b7 [2] c2 ac [2] cd b6 [2] d3 ab [2] d1 aa [2] ca ac [2] d6 ab [2] ca 84 }

  condition:
    any of them
}