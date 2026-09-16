rule TTP_XOR_QUAD_CurrentVersionRun_dd94 {
  strings:
    $key_dd94 = { 8e fb [2] aa f5 [2] 81 d9 [2] af fb [2] bb e0 [2] b4 fa [2] aa e7 [2] a8 e6 [2] b3 e0 [2] af e7 [2] b3 c8 }

  condition:
    any of them
}