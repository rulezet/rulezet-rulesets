rule TTP_XOR_QUAD_CurrentVersionRun_3397 {
  strings:
    $key_3397 = { 60 f8 [2] 44 f6 [2] 6f da [2] 41 f8 [2] 55 e3 [2] 5a f9 [2] 44 e4 [2] 46 e5 [2] 5d e3 [2] 41 e4 [2] 5d cb }

  condition:
    any of them
}