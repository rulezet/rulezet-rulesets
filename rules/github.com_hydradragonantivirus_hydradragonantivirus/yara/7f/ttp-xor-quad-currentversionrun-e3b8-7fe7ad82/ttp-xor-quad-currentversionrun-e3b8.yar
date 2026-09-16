rule TTP_XOR_QUAD_CurrentVersionRun_e3b8 {
  strings:
    $key_e3b8 = { b0 d7 [2] 94 d9 [2] bf f5 [2] 91 d7 [2] 85 cc [2] 8a d6 [2] 94 cb [2] 96 ca [2] 8d cc [2] 91 cb [2] 8d e4 }

  condition:
    any of them
}