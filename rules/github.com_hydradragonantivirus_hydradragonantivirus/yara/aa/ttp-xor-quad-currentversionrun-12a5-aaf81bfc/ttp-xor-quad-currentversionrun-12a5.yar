rule TTP_XOR_QUAD_CurrentVersionRun_12a5 {
  strings:
    $key_12a5 = { 41 ca [2] 65 c4 [2] 4e e8 [2] 60 ca [2] 74 d1 [2] 7b cb [2] 65 d6 [2] 67 d7 [2] 7c d1 [2] 60 d6 [2] 7c f9 }

  condition:
    any of them
}