rule TTP_XOR_QUAD_CurrentVersionRun_7987 {
  strings:
    $key_7987 = { 2a e8 [2] 0e e6 [2] 25 ca [2] 0b e8 [2] 1f f3 [2] 10 e9 [2] 0e f4 [2] 0c f5 [2] 17 f3 [2] 0b f4 [2] 17 db }

  condition:
    any of them
}