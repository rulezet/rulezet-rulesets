rule TTP_XOR_QUAD_CurrentVersionRun_02b8 {
  strings:
    $key_02b8 = { 51 d7 [2] 75 d9 [2] 5e f5 [2] 70 d7 [2] 64 cc [2] 6b d6 [2] 75 cb [2] 77 ca [2] 6c cc [2] 70 cb [2] 6c e4 }

  condition:
    any of them
}