rule TTP_XOR_QUAD_CurrentVersionRun_b6d8 {
  strings:
    $key_b6d8 = { e5 b7 [2] c1 b9 [2] ea 95 [2] c4 b7 [2] d0 ac [2] df b6 [2] c1 ab [2] c3 aa [2] d8 ac [2] c4 ab [2] d8 84 }

  condition:
    any of them
}