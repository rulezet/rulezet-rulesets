rule TTP_XOR_QUAD_CurrentVersionRun_2bb9 {
  strings:
    $key_2bb9 = { 78 d6 [2] 5c d8 [2] 77 f4 [2] 59 d6 [2] 4d cd [2] 42 d7 [2] 5c ca [2] 5e cb [2] 45 cd [2] 59 ca [2] 45 e5 }

  condition:
    any of them
}