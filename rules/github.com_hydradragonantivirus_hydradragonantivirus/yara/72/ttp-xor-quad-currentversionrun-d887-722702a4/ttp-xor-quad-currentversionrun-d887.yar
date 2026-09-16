rule TTP_XOR_QUAD_CurrentVersionRun_d887 {
  strings:
    $key_d887 = { 8b e8 [2] af e6 [2] 84 ca [2] aa e8 [2] be f3 [2] b1 e9 [2] af f4 [2] ad f5 [2] b6 f3 [2] aa f4 [2] b6 db }

  condition:
    any of them
}