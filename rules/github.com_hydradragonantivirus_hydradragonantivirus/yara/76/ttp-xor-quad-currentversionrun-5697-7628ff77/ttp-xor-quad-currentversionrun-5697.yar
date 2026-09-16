rule TTP_XOR_QUAD_CurrentVersionRun_5697 {
  strings:
    $key_5697 = { 05 f8 [2] 21 f6 [2] 0a da [2] 24 f8 [2] 30 e3 [2] 3f f9 [2] 21 e4 [2] 23 e5 [2] 38 e3 [2] 24 e4 [2] 38 cb }

  condition:
    any of them
}