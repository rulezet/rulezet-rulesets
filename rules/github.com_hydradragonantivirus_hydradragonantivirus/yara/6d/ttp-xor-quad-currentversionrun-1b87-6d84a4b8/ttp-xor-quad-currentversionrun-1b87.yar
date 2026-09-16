rule TTP_XOR_QUAD_CurrentVersionRun_1b87 {
  strings:
    $key_1b87 = { 48 e8 [2] 6c e6 [2] 47 ca [2] 69 e8 [2] 7d f3 [2] 72 e9 [2] 6c f4 [2] 6e f5 [2] 75 f3 [2] 69 f4 [2] 75 db }

  condition:
    any of them
}