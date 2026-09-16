rule TTP_XOR_QUAD_CurrentVersionRun_5797 {
  strings:
    $key_5797 = { 04 f8 [2] 20 f6 [2] 0b da [2] 25 f8 [2] 31 e3 [2] 3e f9 [2] 20 e4 [2] 22 e5 [2] 39 e3 [2] 25 e4 [2] 39 cb }

  condition:
    any of them
}