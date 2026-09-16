rule TTP_XOR_QUAD_CurrentVersionRun_dd86 {
  strings:
    $key_dd86 = { 8e e9 [2] aa e7 [2] 81 cb [2] af e9 [2] bb f2 [2] b4 e8 [2] aa f5 [2] a8 f4 [2] b3 f2 [2] af f5 [2] b3 da }

  condition:
    any of them
}