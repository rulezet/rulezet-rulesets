rule TTP_XOR_QUAD_CurrentVersionRun_ebb9 {
  strings:
    $key_ebb9 = { b8 d6 [2] 9c d8 [2] b7 f4 [2] 99 d6 [2] 8d cd [2] 82 d7 [2] 9c ca [2] 9e cb [2] 85 cd [2] 99 ca [2] 85 e5 }

  condition:
    any of them
}