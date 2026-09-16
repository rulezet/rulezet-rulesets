rule TTP_XOR_QUAD_CurrentVersionRun_1bb8 {
  strings:
    $key_1bb8 = { 48 d7 [2] 6c d9 [2] 47 f5 [2] 69 d7 [2] 7d cc [2] 72 d6 [2] 6c cb [2] 6e ca [2] 75 cc [2] 69 cb [2] 75 e4 }

  condition:
    any of them
}