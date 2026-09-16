rule TTP_XOR_QUAD_CurrentVersionRun_5fa4 {
  strings:
    $key_5fa4 = { 0c cb [2] 28 c5 [2] 03 e9 [2] 2d cb [2] 39 d0 [2] 36 ca [2] 28 d7 [2] 2a d6 [2] 31 d0 [2] 2d d7 [2] 31 f8 }

  condition:
    any of them
}