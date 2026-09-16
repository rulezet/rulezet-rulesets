rule TTP_XOR_QUAD_CurrentVersionRun_2fb8 {
  strings:
    $key_2fb8 = { 7c d7 [2] 58 d9 [2] 73 f5 [2] 5d d7 [2] 49 cc [2] 46 d6 [2] 58 cb [2] 5a ca [2] 41 cc [2] 5d cb [2] 41 e4 }

  condition:
    any of them
}