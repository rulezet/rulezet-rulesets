rule TTP_XOR_QUAD_CurrentVersionRun_1697 {
  strings:
    $key_1697 = { 45 f8 [2] 61 f6 [2] 4a da [2] 64 f8 [2] 70 e3 [2] 7f f9 [2] 61 e4 [2] 63 e5 [2] 78 e3 [2] 64 e4 [2] 78 cb }

  condition:
    any of them
}