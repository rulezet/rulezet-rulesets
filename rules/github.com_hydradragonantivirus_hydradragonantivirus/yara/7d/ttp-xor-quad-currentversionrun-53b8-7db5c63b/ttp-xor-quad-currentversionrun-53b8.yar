rule TTP_XOR_QUAD_CurrentVersionRun_53b8 {
  strings:
    $key_53b8 = { 00 d7 [2] 24 d9 [2] 0f f5 [2] 21 d7 [2] 35 cc [2] 3a d6 [2] 24 cb [2] 26 ca [2] 3d cc [2] 21 cb [2] 3d e4 }

  condition:
    any of them
}