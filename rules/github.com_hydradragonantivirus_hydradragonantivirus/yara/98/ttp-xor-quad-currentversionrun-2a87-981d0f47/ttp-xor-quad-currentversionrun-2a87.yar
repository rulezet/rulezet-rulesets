rule TTP_XOR_QUAD_CurrentVersionRun_2a87 {
  strings:
    $key_2a87 = { 79 e8 [2] 5d e6 [2] 76 ca [2] 58 e8 [2] 4c f3 [2] 43 e9 [2] 5d f4 [2] 5f f5 [2] 44 f3 [2] 58 f4 [2] 44 db }

  condition:
    any of them
}