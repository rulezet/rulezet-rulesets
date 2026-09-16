rule TTP_XOR_QUAD_CurrentVersionRun_7397 {
  strings:
    $key_7397 = { 20 f8 [2] 04 f6 [2] 2f da [2] 01 f8 [2] 15 e3 [2] 1a f9 [2] 04 e4 [2] 06 e5 [2] 1d e3 [2] 01 e4 [2] 1d cb }

  condition:
    any of them
}