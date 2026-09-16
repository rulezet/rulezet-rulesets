rule TTP_XOR_QUAD_CurrentVersionRun_52b9 {
  strings:
    $key_52b9 = { 01 d6 [2] 25 d8 [2] 0e f4 [2] 20 d6 [2] 34 cd [2] 3b d7 [2] 25 ca [2] 27 cb [2] 3c cd [2] 20 ca [2] 3c e5 }

  condition:
    any of them
}