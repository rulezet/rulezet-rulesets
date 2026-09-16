rule TTP_XOR_QUAD_CurrentVersionRun_7c87 {
  strings:
    $key_7c87 = { 2f e8 [2] 0b e6 [2] 20 ca [2] 0e e8 [2] 1a f3 [2] 15 e9 [2] 0b f4 [2] 09 f5 [2] 12 f3 [2] 0e f4 [2] 12 db }

  condition:
    any of them
}