rule TTP_XOR_QUAD_CurrentVersionRun_1fb8 {
  strings:
    $key_1fb8 = { 4c d7 [2] 68 d9 [2] 43 f5 [2] 6d d7 [2] 79 cc [2] 76 d6 [2] 68 cb [2] 6a ca [2] 71 cc [2] 6d cb [2] 71 e4 }

  condition:
    any of them
}