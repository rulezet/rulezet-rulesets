rule TTP_XOR_QUAD_CurrentVersionRun_2f97 {
  strings:
    $key_2f97 = { 7c f8 [2] 58 f6 [2] 73 da [2] 5d f8 [2] 49 e3 [2] 46 f9 [2] 58 e4 [2] 5a e5 [2] 41 e3 [2] 5d e4 [2] 41 cb }

  condition:
    any of them
}