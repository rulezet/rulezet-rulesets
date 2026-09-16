rule TTP_XOR_QUAD_CurrentVersionRun_36a4 {
  strings:
    $key_36a4 = { 65 cb [2] 41 c5 [2] 6a e9 [2] 44 cb [2] 50 d0 [2] 5f ca [2] 41 d7 [2] 43 d6 [2] 58 d0 [2] 44 d7 [2] 58 f8 }

  condition:
    any of them
}