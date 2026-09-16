rule TTP_XOR_QUAD_CurrentVersionRun_719b {
  strings:
    $key_719b = { 22 f4 [2] 06 fa [2] 2d d6 [2] 03 f4 [2] 17 ef [2] 18 f5 [2] 06 e8 [2] 04 e9 [2] 1f ef [2] 03 e8 [2] 1f c7 }

  condition:
    any of them
}