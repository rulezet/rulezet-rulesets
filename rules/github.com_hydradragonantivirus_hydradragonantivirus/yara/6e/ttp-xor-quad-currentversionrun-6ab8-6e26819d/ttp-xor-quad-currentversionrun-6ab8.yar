rule TTP_XOR_QUAD_CurrentVersionRun_6ab8 {
  strings:
    $key_6ab8 = { 39 d7 [2] 1d d9 [2] 36 f5 [2] 18 d7 [2] 0c cc [2] 03 d6 [2] 1d cb [2] 1f ca [2] 04 cc [2] 18 cb [2] 04 e4 }

  condition:
    any of them
}