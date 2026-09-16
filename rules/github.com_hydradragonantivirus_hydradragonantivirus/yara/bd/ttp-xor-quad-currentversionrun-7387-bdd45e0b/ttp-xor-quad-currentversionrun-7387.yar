rule TTP_XOR_QUAD_CurrentVersionRun_7387 {
  strings:
    $key_7387 = { 20 e8 [2] 04 e6 [2] 2f ca [2] 01 e8 [2] 15 f3 [2] 1a e9 [2] 04 f4 [2] 06 f5 [2] 1d f3 [2] 01 f4 [2] 1d db }

  condition:
    any of them
}