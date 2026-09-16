rule TTP_XOR_QUAD_CurrentVersionRun_4eb8 {
  strings:
    $key_4eb8 = { 1d d7 [2] 39 d9 [2] 12 f5 [2] 3c d7 [2] 28 cc [2] 27 d6 [2] 39 cb [2] 3b ca [2] 20 cc [2] 3c cb [2] 20 e4 }

  condition:
    any of them
}