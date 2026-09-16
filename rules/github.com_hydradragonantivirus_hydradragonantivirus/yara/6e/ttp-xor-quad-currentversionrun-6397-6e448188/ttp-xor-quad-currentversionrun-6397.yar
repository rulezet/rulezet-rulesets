rule TTP_XOR_QUAD_CurrentVersionRun_6397 {
  strings:
    $key_6397 = { 30 f8 [2] 14 f6 [2] 3f da [2] 11 f8 [2] 05 e3 [2] 0a f9 [2] 14 e4 [2] 16 e5 [2] 0d e3 [2] 11 e4 [2] 0d cb }

  condition:
    any of them
}