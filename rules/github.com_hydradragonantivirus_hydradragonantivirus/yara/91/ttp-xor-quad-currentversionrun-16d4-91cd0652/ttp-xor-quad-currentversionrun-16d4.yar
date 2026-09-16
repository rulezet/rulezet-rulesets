rule TTP_XOR_QUAD_CurrentVersionRun_16d4 {
  strings:
    $key_16d4 = { 45 bb [2] 61 b5 [2] 4a 99 [2] 64 bb [2] 70 a0 [2] 7f ba [2] 61 a7 [2] 63 a6 [2] 78 a0 [2] 64 a7 [2] 78 88 }

  condition:
    any of them
}