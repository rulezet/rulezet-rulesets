rule TTP_XOR_QUAD_CurrentVersionRun_2c87 {
  strings:
    $key_2c87 = { 7f e8 [2] 5b e6 [2] 70 ca [2] 5e e8 [2] 4a f3 [2] 45 e9 [2] 5b f4 [2] 59 f5 [2] 42 f3 [2] 5e f4 [2] 42 db }

  condition:
    any of them
}