rule TTP_XOR_QUAD_CurrentVersionRun_d89b {
  strings:
    $key_d89b = { 8b f4 [2] af fa [2] 84 d6 [2] aa f4 [2] be ef [2] b1 f5 [2] af e8 [2] ad e9 [2] b6 ef [2] aa e8 [2] b6 c7 }

  condition:
    any of them
}