rule TTP_XOR_QUAD_CurrentVersionRun_64a5 {
  strings:
    $key_64a5 = { 37 ca [2] 13 c4 [2] 38 e8 [2] 16 ca [2] 02 d1 [2] 0d cb [2] 13 d6 [2] 11 d7 [2] 0a d1 [2] 16 d6 [2] 0a f9 }

  condition:
    any of them
}