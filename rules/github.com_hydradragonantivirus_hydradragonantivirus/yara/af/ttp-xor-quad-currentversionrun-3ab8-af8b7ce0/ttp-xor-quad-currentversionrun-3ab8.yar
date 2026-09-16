rule TTP_XOR_QUAD_CurrentVersionRun_3ab8 {
  strings:
    $key_3ab8 = { 69 d7 [2] 4d d9 [2] 66 f5 [2] 48 d7 [2] 5c cc [2] 53 d6 [2] 4d cb [2] 4f ca [2] 54 cc [2] 48 cb [2] 54 e4 }

  condition:
    any of them
}