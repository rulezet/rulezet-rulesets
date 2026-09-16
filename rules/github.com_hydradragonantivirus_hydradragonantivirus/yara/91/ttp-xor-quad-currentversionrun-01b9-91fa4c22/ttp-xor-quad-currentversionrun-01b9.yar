rule TTP_XOR_QUAD_CurrentVersionRun_01b9 {
  strings:
    $key_01b9 = { 52 d6 [2] 76 d8 [2] 5d f4 [2] 73 d6 [2] 67 cd [2] 68 d7 [2] 76 ca [2] 74 cb [2] 6f cd [2] 73 ca [2] 6f e5 }

  condition:
    any of them
}