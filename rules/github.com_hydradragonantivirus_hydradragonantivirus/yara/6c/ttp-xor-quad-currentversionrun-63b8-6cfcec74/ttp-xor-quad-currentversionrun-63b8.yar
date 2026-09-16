rule TTP_XOR_QUAD_CurrentVersionRun_63b8 {
  strings:
    $key_63b8 = { 30 d7 [2] 14 d9 [2] 3f f5 [2] 11 d7 [2] 05 cc [2] 0a d6 [2] 14 cb [2] 16 ca [2] 0d cc [2] 11 cb [2] 0d e4 }

  condition:
    any of them
}