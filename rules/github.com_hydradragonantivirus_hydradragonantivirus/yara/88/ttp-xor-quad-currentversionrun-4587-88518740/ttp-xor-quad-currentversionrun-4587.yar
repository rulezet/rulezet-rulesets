rule TTP_XOR_QUAD_CurrentVersionRun_4587 {
  strings:
    $key_4587 = { 16 e8 [2] 32 e6 [2] 19 ca [2] 37 e8 [2] 23 f3 [2] 2c e9 [2] 32 f4 [2] 30 f5 [2] 2b f3 [2] 37 f4 [2] 2b db }

  condition:
    any of them
}