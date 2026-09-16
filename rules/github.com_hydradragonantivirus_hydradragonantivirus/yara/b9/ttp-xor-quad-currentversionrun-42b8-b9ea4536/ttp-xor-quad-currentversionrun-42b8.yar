rule TTP_XOR_QUAD_CurrentVersionRun_42b8 {
  strings:
    $key_42b8 = { 11 d7 [2] 35 d9 [2] 1e f5 [2] 30 d7 [2] 24 cc [2] 2b d6 [2] 35 cb [2] 37 ca [2] 2c cc [2] 30 cb [2] 2c e4 }

  condition:
    any of them
}