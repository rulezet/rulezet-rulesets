rule TTP_XOR_QUAD_CurrentVersionRun_26d4 {
  strings:
    $key_26d4 = { 75 bb [2] 51 b5 [2] 7a 99 [2] 54 bb [2] 40 a0 [2] 4f ba [2] 51 a7 [2] 53 a6 [2] 48 a0 [2] 54 a7 [2] 48 88 }

  condition:
    any of them
}