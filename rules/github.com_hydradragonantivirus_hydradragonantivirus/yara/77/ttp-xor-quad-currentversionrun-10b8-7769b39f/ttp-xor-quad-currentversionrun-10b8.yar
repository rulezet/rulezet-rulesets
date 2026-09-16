rule TTP_XOR_QUAD_CurrentVersionRun_10b8 {
  strings:
    $key_10b8 = { 43 d7 [2] 67 d9 [2] 4c f5 [2] 62 d7 [2] 76 cc [2] 79 d6 [2] 67 cb [2] 65 ca [2] 7e cc [2] 62 cb [2] 7e e4 }

  condition:
    any of them
}