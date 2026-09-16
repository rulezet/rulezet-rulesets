rule TTP_XOR_QUAD_CurrentVersionRun_74b9 {
  strings:
    $key_74b9 = { 27 d6 [2] 03 d8 [2] 28 f4 [2] 06 d6 [2] 12 cd [2] 1d d7 [2] 03 ca [2] 01 cb [2] 1a cd [2] 06 ca [2] 1a e5 }

  condition:
    any of them
}