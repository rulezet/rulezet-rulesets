rule TTP_XOR_QUAD_CurrentVersionRun_3487 {
  strings:
    $key_3487 = { 67 e8 [2] 43 e6 [2] 68 ca [2] 46 e8 [2] 52 f3 [2] 5d e9 [2] 43 f4 [2] 41 f5 [2] 5a f3 [2] 46 f4 [2] 5a db }

  condition:
    any of them
}