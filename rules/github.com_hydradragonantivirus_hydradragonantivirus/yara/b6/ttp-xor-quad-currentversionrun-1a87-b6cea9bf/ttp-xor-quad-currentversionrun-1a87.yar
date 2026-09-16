rule TTP_XOR_QUAD_CurrentVersionRun_1a87 {
  strings:
    $key_1a87 = { 49 e8 [2] 6d e6 [2] 46 ca [2] 68 e8 [2] 7c f3 [2] 73 e9 [2] 6d f4 [2] 6f f5 [2] 74 f3 [2] 68 f4 [2] 74 db }

  condition:
    any of them
}