rule TTP_XOR_QUAD_CurrentVersionRun_6a87 {
  strings:
    $key_6a87 = { 39 e8 [2] 1d e6 [2] 36 ca [2] 18 e8 [2] 0c f3 [2] 03 e9 [2] 1d f4 [2] 1f f5 [2] 04 f3 [2] 18 f4 [2] 04 db }

  condition:
    any of them
}