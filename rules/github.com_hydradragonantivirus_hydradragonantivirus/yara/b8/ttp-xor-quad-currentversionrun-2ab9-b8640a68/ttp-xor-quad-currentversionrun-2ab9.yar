rule TTP_XOR_QUAD_CurrentVersionRun_2ab9 {
  strings:
    $key_2ab9 = { 79 d6 [2] 5d d8 [2] 76 f4 [2] 58 d6 [2] 4c cd [2] 43 d7 [2] 5d ca [2] 5f cb [2] 44 cd [2] 58 ca [2] 44 e5 }

  condition:
    any of them
}