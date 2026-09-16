rule TTP_XOR_QUAD_CurrentVersionRun_7bb8 {
  strings:
    $key_7bb8 = { 28 d7 [2] 0c d9 [2] 27 f5 [2] 09 d7 [2] 1d cc [2] 12 d6 [2] 0c cb [2] 0e ca [2] 15 cc [2] 09 cb [2] 15 e4 }

  condition:
    any of them
}