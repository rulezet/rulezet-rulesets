rule TTP_XOR_QUAD_CurrentVersionRun_dd87 {
  strings:
    $key_dd87 = { 8e e8 [2] aa e6 [2] 81 ca [2] af e8 [2] bb f3 [2] b4 e9 [2] aa f4 [2] a8 f5 [2] b3 f3 [2] af f4 [2] b3 db }

  condition:
    any of them
}