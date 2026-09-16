rule TTP_XOR_QUAD_CurrentVersionRun_499b {
  strings:
    $key_499b = { 1a f4 [2] 3e fa [2] 15 d6 [2] 3b f4 [2] 2f ef [2] 20 f5 [2] 3e e8 [2] 3c e9 [2] 27 ef [2] 3b e8 [2] 27 c7 }

  condition:
    any of them
}