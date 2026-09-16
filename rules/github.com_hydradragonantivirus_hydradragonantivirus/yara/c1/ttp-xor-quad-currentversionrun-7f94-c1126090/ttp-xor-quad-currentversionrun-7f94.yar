rule TTP_XOR_QUAD_CurrentVersionRun_7f94 {
  strings:
    $key_7f94 = { 2c fb [2] 08 f5 [2] 23 d9 [2] 0d fb [2] 19 e0 [2] 16 fa [2] 08 e7 [2] 0a e6 [2] 11 e0 [2] 0d e7 [2] 11 c8 }

  condition:
    any of them
}