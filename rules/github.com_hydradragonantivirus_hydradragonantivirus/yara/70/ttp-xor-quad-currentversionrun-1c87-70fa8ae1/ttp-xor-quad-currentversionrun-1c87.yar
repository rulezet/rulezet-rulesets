rule TTP_XOR_QUAD_CurrentVersionRun_1c87 {
  strings:
    $key_1c87 = { 4f e8 [2] 6b e6 [2] 40 ca [2] 6e e8 [2] 7a f3 [2] 75 e9 [2] 6b f4 [2] 69 f5 [2] 72 f3 [2] 6e f4 [2] 72 db }

  condition:
    any of them
}