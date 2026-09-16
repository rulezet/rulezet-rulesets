rule TTP_XOR_QUAD_CurrentVersionRun_3fa4 {
  strings:
    $key_3fa4 = { 6c cb [2] 48 c5 [2] 63 e9 [2] 4d cb [2] 59 d0 [2] 56 ca [2] 48 d7 [2] 4a d6 [2] 51 d0 [2] 4d d7 [2] 51 f8 }

  condition:
    any of them
}