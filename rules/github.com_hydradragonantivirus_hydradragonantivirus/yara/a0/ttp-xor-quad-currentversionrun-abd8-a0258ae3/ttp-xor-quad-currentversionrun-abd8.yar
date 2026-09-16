rule TTP_XOR_QUAD_CurrentVersionRun_abd8 {
  strings:
    $key_abd8 = { f8 b7 [2] dc b9 [2] f7 95 [2] d9 b7 [2] cd ac [2] c2 b6 [2] dc ab [2] de aa [2] c5 ac [2] d9 ab [2] c5 84 }

  condition:
    any of them
}