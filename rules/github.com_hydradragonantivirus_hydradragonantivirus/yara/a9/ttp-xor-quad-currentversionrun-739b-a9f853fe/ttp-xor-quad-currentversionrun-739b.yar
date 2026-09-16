rule TTP_XOR_QUAD_CurrentVersionRun_739b {
  strings:
    $key_739b = { 20 f4 [2] 04 fa [2] 2f d6 [2] 01 f4 [2] 15 ef [2] 1a f5 [2] 04 e8 [2] 06 e9 [2] 1d ef [2] 01 e8 [2] 1d c7 }

  condition:
    any of them
}