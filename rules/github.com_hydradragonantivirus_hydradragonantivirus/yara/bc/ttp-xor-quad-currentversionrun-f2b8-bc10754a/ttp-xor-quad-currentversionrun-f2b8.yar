rule TTP_XOR_QUAD_CurrentVersionRun_f2b8 {
  strings:
    $key_f2b8 = { a1 d7 [2] 85 d9 [2] ae f5 [2] 80 d7 [2] 94 cc [2] 9b d6 [2] 85 cb [2] 87 ca [2] 9c cc [2] 80 cb [2] 9c e4 }

  condition:
    any of them
}