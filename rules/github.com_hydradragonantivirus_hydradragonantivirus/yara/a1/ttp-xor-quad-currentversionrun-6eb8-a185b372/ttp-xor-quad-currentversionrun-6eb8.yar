rule TTP_XOR_QUAD_CurrentVersionRun_6eb8 {
  strings:
    $key_6eb8 = { 3d d7 [2] 19 d9 [2] 32 f5 [2] 1c d7 [2] 08 cc [2] 07 d6 [2] 19 cb [2] 1b ca [2] 00 cc [2] 1c cb [2] 00 e4 }

  condition:
    any of them
}