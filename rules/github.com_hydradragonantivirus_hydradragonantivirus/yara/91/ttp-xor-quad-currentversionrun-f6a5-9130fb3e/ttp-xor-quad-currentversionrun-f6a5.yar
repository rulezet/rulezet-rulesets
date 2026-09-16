rule TTP_XOR_QUAD_CurrentVersionRun_f6a5 {
  strings:
    $key_f6a5 = { a5 ca [2] 81 c4 [2] aa e8 [2] 84 ca [2] 90 d1 [2] 9f cb [2] 81 d6 [2] 83 d7 [2] 98 d1 [2] 84 d6 [2] 98 f9 }

  condition:
    any of them
}