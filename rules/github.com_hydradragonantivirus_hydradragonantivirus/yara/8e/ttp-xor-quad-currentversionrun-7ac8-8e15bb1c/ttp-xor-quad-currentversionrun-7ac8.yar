rule TTP_XOR_QUAD_CurrentVersionRun_7ac8 {
  strings:
    $key_7ac8 = { 29 a7 [2] 0d a9 [2] 26 85 [2] 08 a7 [2] 1c bc [2] 13 a6 [2] 0d bb [2] 0f ba [2] 14 bc [2] 08 bb [2] 14 94 }

  condition:
    any of them
}