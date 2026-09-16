rule TTP_XOR_QUAD_CurrentVersionRun_4fb8 {
  strings:
    $key_4fb8 = { 1c d7 [2] 38 d9 [2] 13 f5 [2] 3d d7 [2] 29 cc [2] 26 d6 [2] 38 cb [2] 3a ca [2] 21 cc [2] 3d cb [2] 21 e4 }

  condition:
    any of them
}