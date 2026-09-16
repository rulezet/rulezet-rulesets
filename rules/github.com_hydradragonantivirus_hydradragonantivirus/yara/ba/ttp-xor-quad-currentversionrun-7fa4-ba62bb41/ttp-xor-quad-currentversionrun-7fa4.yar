rule TTP_XOR_QUAD_CurrentVersionRun_7fa4 {
  strings:
    $key_7fa4 = { 2c cb [2] 08 c5 [2] 23 e9 [2] 0d cb [2] 19 d0 [2] 16 ca [2] 08 d7 [2] 0a d6 [2] 11 d0 [2] 0d d7 [2] 11 f8 }

  condition:
    any of them
}