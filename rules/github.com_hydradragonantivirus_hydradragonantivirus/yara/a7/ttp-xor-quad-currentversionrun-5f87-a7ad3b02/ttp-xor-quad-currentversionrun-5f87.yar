rule TTP_XOR_QUAD_CurrentVersionRun_5f87 {
  strings:
    $key_5f87 = { 0c e8 [2] 28 e6 [2] 03 ca [2] 2d e8 [2] 39 f3 [2] 36 e9 [2] 28 f4 [2] 2a f5 [2] 31 f3 [2] 2d f4 [2] 31 db }

  condition:
    any of them
}