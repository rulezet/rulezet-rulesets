rule TTP_XOR_QUAD_CurrentVersionRun_22b9 {
  strings:
    $key_22b9 = { 71 d6 [2] 55 d8 [2] 7e f4 [2] 50 d6 [2] 44 cd [2] 4b d7 [2] 55 ca [2] 57 cb [2] 4c cd [2] 50 ca [2] 4c e5 }

  condition:
    any of them
}