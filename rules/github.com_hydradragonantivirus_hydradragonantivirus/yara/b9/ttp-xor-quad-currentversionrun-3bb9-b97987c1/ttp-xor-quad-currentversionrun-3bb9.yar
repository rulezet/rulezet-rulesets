rule TTP_XOR_QUAD_CurrentVersionRun_3bb9 {
  strings:
    $key_3bb9 = { 68 d6 [2] 4c d8 [2] 67 f4 [2] 49 d6 [2] 5d cd [2] 52 d7 [2] 4c ca [2] 4e cb [2] 55 cd [2] 49 ca [2] 55 e5 }

  condition:
    any of them
}