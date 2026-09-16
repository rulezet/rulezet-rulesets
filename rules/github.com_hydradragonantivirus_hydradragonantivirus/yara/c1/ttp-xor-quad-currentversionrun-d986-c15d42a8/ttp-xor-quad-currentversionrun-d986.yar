rule TTP_XOR_QUAD_CurrentVersionRun_d986 {
  strings:
    $key_d986 = { 8a e9 [2] ae e7 [2] 85 cb [2] ab e9 [2] bf f2 [2] b0 e8 [2] ae f5 [2] ac f4 [2] b7 f2 [2] ab f5 [2] b7 da }

  condition:
    any of them
}