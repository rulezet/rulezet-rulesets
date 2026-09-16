rule TTP_XOR_QUAD_CurrentVersionRun_4e94 {
  strings:
    $key_4e94 = { 1d fb [2] 39 f5 [2] 12 d9 [2] 3c fb [2] 28 e0 [2] 27 fa [2] 39 e7 [2] 3b e6 [2] 20 e0 [2] 3c e7 [2] 20 c8 }

  condition:
    any of them
}