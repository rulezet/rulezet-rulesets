rule TTP_XOR_QUAD_CurrentVersionRun_04b9 {
  strings:
    $key_04b9 = { 57 d6 [2] 73 d8 [2] 58 f4 [2] 76 d6 [2] 62 cd [2] 6d d7 [2] 73 ca [2] 71 cb [2] 6a cd [2] 76 ca [2] 6a e5 }

  condition:
    any of them
}