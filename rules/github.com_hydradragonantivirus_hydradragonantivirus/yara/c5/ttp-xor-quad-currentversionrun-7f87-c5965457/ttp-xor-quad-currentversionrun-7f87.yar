rule TTP_XOR_QUAD_CurrentVersionRun_7f87 {
  strings:
    $key_7f87 = { 2c e8 [2] 08 e6 [2] 23 ca [2] 0d e8 [2] 19 f3 [2] 16 e9 [2] 08 f4 [2] 0a f5 [2] 11 f3 [2] 0d f4 [2] 11 db }

  condition:
    any of them
}