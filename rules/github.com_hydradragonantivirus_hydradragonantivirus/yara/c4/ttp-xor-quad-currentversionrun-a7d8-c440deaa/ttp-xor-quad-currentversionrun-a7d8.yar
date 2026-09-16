rule TTP_XOR_QUAD_CurrentVersionRun_a7d8 {
  strings:
    $key_a7d8 = { f4 b7 [2] d0 b9 [2] fb 95 [2] d5 b7 [2] c1 ac [2] ce b6 [2] d0 ab [2] d2 aa [2] c9 ac [2] d5 ab [2] c9 84 }

  condition:
    any of them
}