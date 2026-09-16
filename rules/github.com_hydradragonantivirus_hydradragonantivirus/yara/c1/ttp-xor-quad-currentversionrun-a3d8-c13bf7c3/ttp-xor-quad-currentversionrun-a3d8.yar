rule TTP_XOR_QUAD_CurrentVersionRun_a3d8 {
  strings:
    $key_a3d8 = { f0 b7 [2] d4 b9 [2] ff 95 [2] d1 b7 [2] c5 ac [2] ca b6 [2] d4 ab [2] d6 aa [2] cd ac [2] d1 ab [2] cd 84 }

  condition:
    any of them
}