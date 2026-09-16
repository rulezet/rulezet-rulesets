rule TTP_XOR_QUAD_CurrentVersionRun_f6b8 {
  strings:
    $key_f6b8 = { a5 d7 [2] 81 d9 [2] aa f5 [2] 84 d7 [2] 90 cc [2] 9f d6 [2] 81 cb [2] 83 ca [2] 98 cc [2] 84 cb [2] 98 e4 }

  condition:
    any of them
}