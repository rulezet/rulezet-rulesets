rule TTP_XOR_QUAD_CurrentVersionRun_6697 {
  strings:
    $key_6697 = { 35 f8 [2] 11 f6 [2] 3a da [2] 14 f8 [2] 00 e3 [2] 0f f9 [2] 11 e4 [2] 13 e5 [2] 08 e3 [2] 14 e4 [2] 08 cb }

  condition:
    any of them
}