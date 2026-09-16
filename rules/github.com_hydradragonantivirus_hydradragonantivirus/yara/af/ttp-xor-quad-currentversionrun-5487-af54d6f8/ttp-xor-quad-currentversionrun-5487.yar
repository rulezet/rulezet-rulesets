rule TTP_XOR_QUAD_CurrentVersionRun_5487 {
  strings:
    $key_5487 = { 07 e8 [2] 23 e6 [2] 08 ca [2] 26 e8 [2] 32 f3 [2] 3d e9 [2] 23 f4 [2] 21 f5 [2] 3a f3 [2] 26 f4 [2] 3a db }

  condition:
    any of them
}