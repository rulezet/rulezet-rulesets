rule TTP_XOR_QUAD_CurrentVersionRun_6f87 {
  strings:
    $key_6f87 = { 3c e8 [2] 18 e6 [2] 33 ca [2] 1d e8 [2] 09 f3 [2] 06 e9 [2] 18 f4 [2] 1a f5 [2] 01 f3 [2] 1d f4 [2] 01 db }

  condition:
    any of them
}