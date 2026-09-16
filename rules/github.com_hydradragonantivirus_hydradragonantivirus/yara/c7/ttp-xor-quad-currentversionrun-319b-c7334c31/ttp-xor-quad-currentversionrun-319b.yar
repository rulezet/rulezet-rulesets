rule TTP_XOR_QUAD_CurrentVersionRun_319b {
  strings:
    $key_319b = { 62 f4 [2] 46 fa [2] 6d d6 [2] 43 f4 [2] 57 ef [2] 58 f5 [2] 46 e8 [2] 44 e9 [2] 5f ef [2] 43 e8 [2] 5f c7 }

  condition:
    any of them
}