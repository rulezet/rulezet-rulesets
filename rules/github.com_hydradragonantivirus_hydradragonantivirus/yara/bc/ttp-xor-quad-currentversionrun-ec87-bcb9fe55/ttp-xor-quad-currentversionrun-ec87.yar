rule TTP_XOR_QUAD_CurrentVersionRun_ec87 {
  strings:
    $key_ec87 = { bf e8 [2] 9b e6 [2] b0 ca [2] 9e e8 [2] 8a f3 [2] 85 e9 [2] 9b f4 [2] 99 f5 [2] 82 f3 [2] 9e f4 [2] 82 db }

  condition:
    any of them
}