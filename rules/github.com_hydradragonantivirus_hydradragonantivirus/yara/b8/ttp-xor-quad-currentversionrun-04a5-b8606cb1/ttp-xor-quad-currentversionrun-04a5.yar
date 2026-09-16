rule TTP_XOR_QUAD_CurrentVersionRun_04a5 {
  strings:
    $key_04a5 = { 57 ca [2] 73 c4 [2] 58 e8 [2] 76 ca [2] 62 d1 [2] 6d cb [2] 73 d6 [2] 71 d7 [2] 6a d1 [2] 76 d6 [2] 6a f9 }

  condition:
    any of them
}