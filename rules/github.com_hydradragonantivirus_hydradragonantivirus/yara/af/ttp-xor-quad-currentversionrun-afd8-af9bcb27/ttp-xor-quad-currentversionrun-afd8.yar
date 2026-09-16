rule TTP_XOR_QUAD_CurrentVersionRun_afd8 {
  strings:
    $key_afd8 = { fc b7 [2] d8 b9 [2] f3 95 [2] dd b7 [2] c9 ac [2] c6 b6 [2] d8 ab [2] da aa [2] c1 ac [2] dd ab [2] c1 84 }

  condition:
    any of them
}