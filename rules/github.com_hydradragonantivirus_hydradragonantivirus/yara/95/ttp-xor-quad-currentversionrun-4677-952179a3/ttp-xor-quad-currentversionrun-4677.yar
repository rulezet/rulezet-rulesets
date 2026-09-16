rule TTP_XOR_QUAD_CurrentVersionRun_4677 {
  strings:
    $key_4677 = { 15 18 [2] 31 16 [2] 1a 3a [2] 34 18 [2] 20 03 [2] 2f 19 [2] 31 04 [2] 33 05 [2] 28 03 [2] 34 04 [2] 28 2b }

  condition:
    any of them
}