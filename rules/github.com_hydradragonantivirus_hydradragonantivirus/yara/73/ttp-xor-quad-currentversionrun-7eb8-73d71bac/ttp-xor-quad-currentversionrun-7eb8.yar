rule TTP_XOR_QUAD_CurrentVersionRun_7eb8 {
  strings:
    $key_7eb8 = { 2d d7 [2] 09 d9 [2] 22 f5 [2] 0c d7 [2] 18 cc [2] 17 d6 [2] 09 cb [2] 0b ca [2] 10 cc [2] 0c cb [2] 10 e4 }

  condition:
    any of them
}