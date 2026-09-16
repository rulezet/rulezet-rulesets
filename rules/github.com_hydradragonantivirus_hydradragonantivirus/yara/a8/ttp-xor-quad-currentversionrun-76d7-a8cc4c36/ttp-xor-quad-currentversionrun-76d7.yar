rule TTP_XOR_QUAD_CurrentVersionRun_76d7 {
  strings:
    $key_76d7 = { 25 b8 [2] 01 b6 [2] 2a 9a [2] 04 b8 [2] 10 a3 [2] 1f b9 [2] 01 a4 [2] 03 a5 [2] 18 a3 [2] 04 a4 [2] 18 8b }

  condition:
    any of them
}