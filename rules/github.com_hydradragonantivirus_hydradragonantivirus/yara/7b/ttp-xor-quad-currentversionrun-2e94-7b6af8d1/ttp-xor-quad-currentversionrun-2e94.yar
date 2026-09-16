rule TTP_XOR_QUAD_CurrentVersionRun_2e94 {
  strings:
    $key_2e94 = { 7d fb [2] 59 f5 [2] 72 d9 [2] 5c fb [2] 48 e0 [2] 47 fa [2] 59 e7 [2] 5b e6 [2] 40 e0 [2] 5c e7 [2] 40 c8 }

  condition:
    any of them
}