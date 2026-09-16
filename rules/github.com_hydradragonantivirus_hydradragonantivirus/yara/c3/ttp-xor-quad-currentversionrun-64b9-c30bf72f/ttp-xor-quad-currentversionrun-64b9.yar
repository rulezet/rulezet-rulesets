rule TTP_XOR_QUAD_CurrentVersionRun_64b9 {
  strings:
    $key_64b9 = { 37 d6 [2] 13 d8 [2] 38 f4 [2] 16 d6 [2] 02 cd [2] 0d d7 [2] 13 ca [2] 11 cb [2] 0a cd [2] 16 ca [2] 0a e5 }

  condition:
    any of them
}