rule TTP_XOR_QUAD_CurrentVersionRun_b3c4 {
  strings:
    $key_b3c4 = { e0 ab [2] c4 a5 [2] ef 89 [2] c1 ab [2] d5 b0 [2] da aa [2] c4 b7 [2] c6 b6 [2] dd b0 [2] c1 b7 [2] dd 98 }

  condition:
    any of them
}