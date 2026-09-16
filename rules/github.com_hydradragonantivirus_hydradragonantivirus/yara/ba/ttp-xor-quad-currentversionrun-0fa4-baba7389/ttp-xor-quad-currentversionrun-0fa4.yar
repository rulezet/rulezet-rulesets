rule TTP_XOR_QUAD_CurrentVersionRun_0fa4 {
  strings:
    $key_0fa4 = { 5c cb [2] 78 c5 [2] 53 e9 [2] 7d cb [2] 69 d0 [2] 66 ca [2] 78 d7 [2] 7a d6 [2] 61 d0 [2] 7d d7 [2] 61 f8 }

  condition:
    any of them
}