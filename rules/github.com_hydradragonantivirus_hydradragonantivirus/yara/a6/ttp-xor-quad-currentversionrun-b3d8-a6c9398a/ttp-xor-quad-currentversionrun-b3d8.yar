rule TTP_XOR_QUAD_CurrentVersionRun_b3d8 {
  strings:
    $key_b3d8 = { e0 b7 [2] c4 b9 [2] ef 95 [2] c1 b7 [2] d5 ac [2] da b6 [2] c4 ab [2] c6 aa [2] dd ac [2] c1 ab [2] dd 84 }

  condition:
    any of them
}