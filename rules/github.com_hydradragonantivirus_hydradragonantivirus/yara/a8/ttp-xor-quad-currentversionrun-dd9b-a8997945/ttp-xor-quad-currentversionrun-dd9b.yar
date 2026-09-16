rule TTP_XOR_QUAD_CurrentVersionRun_dd9b {
  strings:
    $key_dd9b = { 8e f4 [2] aa fa [2] 81 d6 [2] af f4 [2] bb ef [2] b4 f5 [2] aa e8 [2] a8 e9 [2] b3 ef [2] af e8 [2] b3 c7 }

  condition:
    any of them
}