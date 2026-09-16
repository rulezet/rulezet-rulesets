rule TTP_XOR_QUAD_CurrentVersionRun_e5b8 {
  strings:
    $key_e5b8 = { b6 d7 [2] 92 d9 [2] b9 f5 [2] 97 d7 [2] 83 cc [2] 8c d6 [2] 92 cb [2] 90 ca [2] 8b cc [2] 97 cb [2] 8b e4 }

  condition:
    any of them
}