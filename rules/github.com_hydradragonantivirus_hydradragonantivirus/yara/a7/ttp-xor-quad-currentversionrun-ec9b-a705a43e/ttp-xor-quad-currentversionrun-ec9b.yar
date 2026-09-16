rule TTP_XOR_QUAD_CurrentVersionRun_ec9b {
  strings:
    $key_ec9b = { bf f4 [2] 9b fa [2] b0 d6 [2] 9e f4 [2] 8a ef [2] 85 f5 [2] 9b e8 [2] 99 e9 [2] 82 ef [2] 9e e8 [2] 82 c7 }

  condition:
    any of them
}