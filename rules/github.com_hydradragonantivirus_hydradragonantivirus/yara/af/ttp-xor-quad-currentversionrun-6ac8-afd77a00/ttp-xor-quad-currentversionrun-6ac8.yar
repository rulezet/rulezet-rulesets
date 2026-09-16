rule TTP_XOR_QUAD_CurrentVersionRun_6ac8 {
  strings:
    $key_6ac8 = { 39 a7 [2] 1d a9 [2] 36 85 [2] 18 a7 [2] 0c bc [2] 03 a6 [2] 1d bb [2] 1f ba [2] 04 bc [2] 18 bb [2] 04 94 }

  condition:
    any of them
}