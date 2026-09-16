rule TTP_XOR_QUAD_CurrentVersionRun_a5d8 {
  strings:
    $key_a5d8 = { f6 b7 [2] d2 b9 [2] f9 95 [2] d7 b7 [2] c3 ac [2] cc b6 [2] d2 ab [2] d0 aa [2] cb ac [2] d7 ab [2] cb 84 }

  condition:
    any of them
}