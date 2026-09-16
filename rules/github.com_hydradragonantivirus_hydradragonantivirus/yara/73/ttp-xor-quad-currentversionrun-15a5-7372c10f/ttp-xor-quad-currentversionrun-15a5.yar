rule TTP_XOR_QUAD_CurrentVersionRun_15a5 {
  strings:
    $key_15a5 = { 46 ca [2] 62 c4 [2] 49 e8 [2] 67 ca [2] 73 d1 [2] 7c cb [2] 62 d6 [2] 60 d7 [2] 7b d1 [2] 67 d6 [2] 7b f9 }

  condition:
    any of them
}