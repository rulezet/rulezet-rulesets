rule TTP_XOR_QUAD_CurrentVersionRun_55b9 {
  strings:
    $key_55b9 = { 06 d6 [2] 22 d8 [2] 09 f4 [2] 27 d6 [2] 33 cd [2] 3c d7 [2] 22 ca [2] 20 cb [2] 3b cd [2] 27 ca [2] 3b e5 }

  condition:
    any of them
}