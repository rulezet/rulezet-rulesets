rule TTP_XOR_QUAD_CurrentVersionRun_06d4 {
  strings:
    $key_06d4 = { 55 bb [2] 71 b5 [2] 5a 99 [2] 74 bb [2] 60 a0 [2] 6f ba [2] 71 a7 [2] 73 a6 [2] 68 a0 [2] 74 a7 [2] 68 88 }

  condition:
    any of them
}