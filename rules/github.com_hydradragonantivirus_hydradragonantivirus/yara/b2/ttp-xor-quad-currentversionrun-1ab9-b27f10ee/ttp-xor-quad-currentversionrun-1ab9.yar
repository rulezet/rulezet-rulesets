rule TTP_XOR_QUAD_CurrentVersionRun_1ab9 {
  strings:
    $key_1ab9 = { 49 d6 [2] 6d d8 [2] 46 f4 [2] 68 d6 [2] 7c cd [2] 73 d7 [2] 6d ca [2] 6f cb [2] 74 cd [2] 68 ca [2] 74 e5 }

  condition:
    any of them
}