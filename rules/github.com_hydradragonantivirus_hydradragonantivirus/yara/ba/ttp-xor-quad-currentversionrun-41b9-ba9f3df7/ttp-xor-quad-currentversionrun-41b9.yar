rule TTP_XOR_QUAD_CurrentVersionRun_41b9 {
  strings:
    $key_41b9 = { 12 d6 [2] 36 d8 [2] 1d f4 [2] 33 d6 [2] 27 cd [2] 28 d7 [2] 36 ca [2] 34 cb [2] 2f cd [2] 33 ca [2] 2f e5 }

  condition:
    any of them
}