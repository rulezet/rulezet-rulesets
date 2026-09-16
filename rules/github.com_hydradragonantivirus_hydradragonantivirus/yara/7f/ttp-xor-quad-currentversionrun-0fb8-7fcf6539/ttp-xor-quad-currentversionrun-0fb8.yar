rule TTP_XOR_QUAD_CurrentVersionRun_0fb8 {
  strings:
    $key_0fb8 = { 5c d7 [2] 78 d9 [2] 53 f5 [2] 7d d7 [2] 69 cc [2] 66 d6 [2] 78 cb [2] 7a ca [2] 61 cc [2] 7d cb [2] 61 e4 }

  condition:
    any of them
}