rule TTP_XOR_QUAD_CurrentVersionRun_3797 {
  strings:
    $key_3797 = { 64 f8 [2] 40 f6 [2] 6b da [2] 45 f8 [2] 51 e3 [2] 5e f9 [2] 40 e4 [2] 42 e5 [2] 59 e3 [2] 45 e4 [2] 59 cb }

  condition:
    any of them
}