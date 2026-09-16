rule TTP_XOR_QUAD_CurrentVersionRun_7a87 {
  strings:
    $key_7a87 = { 29 e8 [2] 0d e6 [2] 26 ca [2] 08 e8 [2] 1c f3 [2] 13 e9 [2] 0d f4 [2] 0f f5 [2] 14 f3 [2] 08 f4 [2] 14 db }

  condition:
    any of them
}