rule TTP_XOR_QUAD_CurrentVersionRun_03b8 {
  strings:
    $key_03b8 = { 50 d7 [2] 74 d9 [2] 5f f5 [2] 71 d7 [2] 65 cc [2] 6a d6 [2] 74 cb [2] 76 ca [2] 6d cc [2] 71 cb [2] 6d e4 }

  condition:
    any of them
}