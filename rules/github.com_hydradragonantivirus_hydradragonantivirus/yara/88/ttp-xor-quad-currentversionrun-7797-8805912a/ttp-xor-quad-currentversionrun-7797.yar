rule TTP_XOR_QUAD_CurrentVersionRun_7797 {
  strings:
    $key_7797 = { 24 f8 [2] 00 f6 [2] 2b da [2] 05 f8 [2] 11 e3 [2] 1e f9 [2] 00 e4 [2] 02 e5 [2] 19 e3 [2] 05 e4 [2] 19 cb }

  condition:
    any of them
}