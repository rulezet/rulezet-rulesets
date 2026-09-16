rule TTP_XOR_QUAD_CurrentVersionRun_3486 {
  strings:
    $key_3486 = { 67 e9 [2] 43 e7 [2] 68 cb [2] 46 e9 [2] 52 f2 [2] 5d e8 [2] 43 f5 [2] 41 f4 [2] 5a f2 [2] 46 f5 [2] 5a da }

  condition:
    any of them
}