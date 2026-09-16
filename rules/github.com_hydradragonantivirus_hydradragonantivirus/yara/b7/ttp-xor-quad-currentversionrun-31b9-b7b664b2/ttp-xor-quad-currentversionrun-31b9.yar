rule TTP_XOR_QUAD_CurrentVersionRun_31b9 {
  strings:
    $key_31b9 = { 62 d6 [2] 46 d8 [2] 6d f4 [2] 43 d6 [2] 57 cd [2] 58 d7 [2] 46 ca [2] 44 cb [2] 5f cd [2] 43 ca [2] 5f e5 }

  condition:
    any of them
}