rule TTP_XOR_QUAD_CurrentVersionRun_65b9 {
  strings:
    $key_65b9 = { 36 d6 [2] 12 d8 [2] 39 f4 [2] 17 d6 [2] 03 cd [2] 0c d7 [2] 12 ca [2] 10 cb [2] 0b cd [2] 17 ca [2] 0b e5 }

  condition:
    any of them
}