rule TTP_XOR_QUAD_CurrentVersionRun_0a87 {
  strings:
    $key_0a87 = { 59 e8 [2] 7d e6 [2] 56 ca [2] 78 e8 [2] 6c f3 [2] 63 e9 [2] 7d f4 [2] 7f f5 [2] 64 f3 [2] 78 f4 [2] 64 db }

  condition:
    any of them
}