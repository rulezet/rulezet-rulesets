rule TTP_XOR_QUAD_CurrentVersionRun_3ab9 {
  strings:
    $key_3ab9 = { 69 d6 [2] 4d d8 [2] 66 f4 [2] 48 d6 [2] 5c cd [2] 53 d7 [2] 4d ca [2] 4f cb [2] 54 cd [2] 48 ca [2] 54 e5 }

  condition:
    any of them
}