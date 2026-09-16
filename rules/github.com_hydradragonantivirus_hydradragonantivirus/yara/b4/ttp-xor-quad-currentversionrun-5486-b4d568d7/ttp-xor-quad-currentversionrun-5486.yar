rule TTP_XOR_QUAD_CurrentVersionRun_5486 {
  strings:
    $key_5486 = { 07 e9 [2] 23 e7 [2] 08 cb [2] 26 e9 [2] 32 f2 [2] 3d e8 [2] 23 f5 [2] 21 f4 [2] 3a f2 [2] 26 f5 [2] 3a da }

  condition:
    any of them
}