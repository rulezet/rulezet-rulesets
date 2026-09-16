rule TTP_XOR_QUAD_CurrentVersionRun_4ac8 {
  strings:
    $key_4ac8 = { 19 a7 [2] 3d a9 [2] 16 85 [2] 38 a7 [2] 2c bc [2] 23 a6 [2] 3d bb [2] 3f ba [2] 24 bc [2] 38 bb [2] 24 94 }

  condition:
    any of them
}