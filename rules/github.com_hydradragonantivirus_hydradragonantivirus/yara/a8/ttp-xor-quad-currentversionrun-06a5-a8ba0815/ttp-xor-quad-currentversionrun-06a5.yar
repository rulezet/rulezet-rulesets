rule TTP_XOR_QUAD_CurrentVersionRun_06a5 {
  strings:
    $key_06a5 = { 55 ca [2] 71 c4 [2] 5a e8 [2] 74 ca [2] 60 d1 [2] 6f cb [2] 71 d6 [2] 73 d7 [2] 68 d1 [2] 74 d6 [2] 68 f9 }

  condition:
    any of them
}