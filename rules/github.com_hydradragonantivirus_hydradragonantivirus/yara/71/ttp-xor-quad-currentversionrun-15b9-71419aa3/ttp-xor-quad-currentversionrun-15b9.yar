rule TTP_XOR_QUAD_CurrentVersionRun_15b9 {
  strings:
    $key_15b9 = { 46 d6 [2] 62 d8 [2] 49 f4 [2] 67 d6 [2] 73 cd [2] 7c d7 [2] 62 ca [2] 60 cb [2] 7b cd [2] 67 ca [2] 7b e5 }

  condition:
    any of them
}