rule TTP_XOR_QUAD_CurrentVersionRun_0ab8 {
  strings:
    $key_0ab8 = { 59 d7 [2] 7d d9 [2] 56 f5 [2] 78 d7 [2] 6c cc [2] 63 d6 [2] 7d cb [2] 7f ca [2] 64 cc [2] 78 cb [2] 64 e4 }

  condition:
    any of them
}