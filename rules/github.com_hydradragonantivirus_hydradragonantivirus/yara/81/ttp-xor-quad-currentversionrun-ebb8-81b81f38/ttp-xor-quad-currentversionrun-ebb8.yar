rule TTP_XOR_QUAD_CurrentVersionRun_ebb8 {
  strings:
    $key_ebb8 = { b8 d7 [2] 9c d9 [2] b7 f5 [2] 99 d7 [2] 8d cc [2] 82 d6 [2] 9c cb [2] 9e ca [2] 85 cc [2] 99 cb [2] 85 e4 }

  condition:
    any of them
}