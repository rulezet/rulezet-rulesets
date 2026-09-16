rule TTP_XOR_QUAD_CurrentVersionRun_1797 {
  strings:
    $key_1797 = { 44 f8 [2] 60 f6 [2] 4b da [2] 65 f8 [2] 71 e3 [2] 7e f9 [2] 60 e4 [2] 62 e5 [2] 79 e3 [2] 65 e4 [2] 79 cb }

  condition:
    any of them
}