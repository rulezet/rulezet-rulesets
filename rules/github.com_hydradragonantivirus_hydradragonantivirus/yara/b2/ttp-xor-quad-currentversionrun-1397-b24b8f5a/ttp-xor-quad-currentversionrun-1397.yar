rule TTP_XOR_QUAD_CurrentVersionRun_1397 {
  strings:
    $key_1397 = { 40 f8 [2] 64 f6 [2] 4f da [2] 61 f8 [2] 75 e3 [2] 7a f9 [2] 64 e4 [2] 66 e5 [2] 7d e3 [2] 61 e4 [2] 7d cb }

  condition:
    any of them
}