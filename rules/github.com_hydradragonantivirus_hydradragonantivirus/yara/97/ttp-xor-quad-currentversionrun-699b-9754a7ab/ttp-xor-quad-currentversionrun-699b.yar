rule TTP_XOR_QUAD_CurrentVersionRun_699b {
  strings:
    $key_699b = { 3a f4 [2] 1e fa [2] 35 d6 [2] 1b f4 [2] 0f ef [2] 00 f5 [2] 1e e8 [2] 1c e9 [2] 07 ef [2] 1b e8 [2] 07 c7 }

  condition:
    any of them
}