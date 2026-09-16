rule TTP_XOR_QUAD_CurrentVersionRun_d886 {
  strings:
    $key_d886 = { 8b e9 [2] af e7 [2] 84 cb [2] aa e9 [2] be f2 [2] b1 e8 [2] af f5 [2] ad f4 [2] b6 f2 [2] aa f5 [2] b6 da }

  condition:
    any of them
}