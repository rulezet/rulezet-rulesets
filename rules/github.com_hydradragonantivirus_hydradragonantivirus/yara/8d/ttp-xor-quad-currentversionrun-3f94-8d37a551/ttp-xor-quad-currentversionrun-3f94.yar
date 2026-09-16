rule TTP_XOR_QUAD_CurrentVersionRun_3f94 {
  strings:
    $key_3f94 = { 6c fb [2] 48 f5 [2] 63 d9 [2] 4d fb [2] 59 e0 [2] 56 fa [2] 48 e7 [2] 4a e6 [2] 51 e0 [2] 4d e7 [2] 51 c8 }

  condition:
    any of them
}