rule TTP_XOR_QUAD_CurrentVersionRun_7697 {
  strings:
    $key_7697 = { 25 f8 [2] 01 f6 [2] 2a da [2] 04 f8 [2] 10 e3 [2] 1f f9 [2] 01 e4 [2] 03 e5 [2] 18 e3 [2] 04 e4 [2] 18 cb }

  condition:
    any of them
}