rule TTP_XOR_QUAD_CurrentVersionRun_2397 {
  strings:
    $key_2397 = { 70 f8 [2] 54 f6 [2] 7f da [2] 51 f8 [2] 45 e3 [2] 4a f9 [2] 54 e4 [2] 56 e5 [2] 4d e3 [2] 51 e4 [2] 4d cb }

  condition:
    any of them
}