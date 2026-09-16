rule TTP_XOR_QUAD_CurrentVersionRun_5087 {
  strings:
    $key_5087 = { 03 e8 [2] 27 e6 [2] 0c ca [2] 22 e8 [2] 36 f3 [2] 39 e9 [2] 27 f4 [2] 25 f5 [2] 3e f3 [2] 22 f4 [2] 3e db }

  condition:
    any of them
}