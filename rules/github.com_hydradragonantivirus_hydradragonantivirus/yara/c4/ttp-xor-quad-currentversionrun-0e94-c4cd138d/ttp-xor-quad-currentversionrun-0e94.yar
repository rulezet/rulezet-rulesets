rule TTP_XOR_QUAD_CurrentVersionRun_0e94 {
  strings:
    $key_0e94 = { 5d fb [2] 79 f5 [2] 52 d9 [2] 7c fb [2] 68 e0 [2] 67 fa [2] 79 e7 [2] 7b e6 [2] 60 e0 [2] 7c e7 [2] 60 c8 }

  condition:
    any of them
}