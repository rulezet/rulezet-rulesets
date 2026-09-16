rule TTP_XOR_QUAD_CurrentVersionRun_2f94 {
  strings:
    $key_2f94 = { 7c fb [2] 58 f5 [2] 73 d9 [2] 5d fb [2] 49 e0 [2] 46 fa [2] 58 e7 [2] 5a e6 [2] 41 e0 [2] 5d e7 [2] 41 c8 }

  condition:
    any of them
}