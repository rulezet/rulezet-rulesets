rule TTP_XOR_QUAD_CurrentVersionRun_d987 {
  strings:
    $key_d987 = { 8a e8 [2] ae e6 [2] 85 ca [2] ab e8 [2] bf f3 [2] b0 e9 [2] ae f4 [2] ac f5 [2] b7 f3 [2] ab f4 [2] b7 db }

  condition:
    any of them
}