rule TTP_XOR_QUAD_CurrentVersionRun_5e94 {
  strings:
    $key_5e94 = { 0d fb [2] 29 f5 [2] 02 d9 [2] 2c fb [2] 38 e0 [2] 37 fa [2] 29 e7 [2] 2b e6 [2] 30 e0 [2] 2c e7 [2] 30 c8 }

  condition:
    any of them
}