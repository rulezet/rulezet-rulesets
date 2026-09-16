rule TTP_XOR_QUAD_CurrentVersionRun_09b8 {
  strings:
    $key_09b8 = { 5a d7 [2] 7e d9 [2] 55 f5 [2] 7b d7 [2] 6f cc [2] 60 d6 [2] 7e cb [2] 7c ca [2] 67 cc [2] 7b cb [2] 67 e4 }

  condition:
    any of them
}