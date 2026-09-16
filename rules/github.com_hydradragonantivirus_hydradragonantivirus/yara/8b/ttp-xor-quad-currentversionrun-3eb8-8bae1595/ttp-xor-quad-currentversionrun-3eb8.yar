rule TTP_XOR_QUAD_CurrentVersionRun_3eb8 {
  strings:
    $key_3eb8 = { 6d d7 [2] 49 d9 [2] 62 f5 [2] 4c d7 [2] 58 cc [2] 57 d6 [2] 49 cb [2] 4b ca [2] 50 cc [2] 4c cb [2] 50 e4 }

  condition:
    any of them
}