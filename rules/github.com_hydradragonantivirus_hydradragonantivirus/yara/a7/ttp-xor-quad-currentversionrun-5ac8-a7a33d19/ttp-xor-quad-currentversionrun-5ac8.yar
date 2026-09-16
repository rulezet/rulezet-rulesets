rule TTP_XOR_QUAD_CurrentVersionRun_5ac8 {
  strings:
    $key_5ac8 = { 09 a7 [2] 2d a9 [2] 06 85 [2] 28 a7 [2] 3c bc [2] 33 a6 [2] 2d bb [2] 2f ba [2] 34 bc [2] 28 bb [2] 34 94 }

  condition:
    any of them
}