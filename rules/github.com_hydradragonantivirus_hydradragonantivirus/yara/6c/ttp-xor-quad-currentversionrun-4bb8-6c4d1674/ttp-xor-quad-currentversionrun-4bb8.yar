rule TTP_XOR_QUAD_CurrentVersionRun_4bb8 {
  strings:
    $key_4bb8 = { 18 d7 [2] 3c d9 [2] 17 f5 [2] 39 d7 [2] 2d cc [2] 22 d6 [2] 3c cb [2] 3e ca [2] 25 cc [2] 39 cb [2] 25 e4 }

  condition:
    any of them
}