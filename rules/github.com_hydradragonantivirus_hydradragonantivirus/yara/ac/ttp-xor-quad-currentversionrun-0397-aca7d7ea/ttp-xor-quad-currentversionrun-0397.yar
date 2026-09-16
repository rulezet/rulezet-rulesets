rule TTP_XOR_QUAD_CurrentVersionRun_0397 {
  strings:
    $key_0397 = { 50 f8 [2] 74 f6 [2] 5f da [2] 71 f8 [2] 65 e3 [2] 6a f9 [2] 74 e4 [2] 76 e5 [2] 6d e3 [2] 71 e4 [2] 6d cb }

  condition:
    any of them
}