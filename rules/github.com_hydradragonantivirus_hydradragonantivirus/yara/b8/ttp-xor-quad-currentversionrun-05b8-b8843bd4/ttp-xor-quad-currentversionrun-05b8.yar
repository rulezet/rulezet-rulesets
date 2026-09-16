rule TTP_XOR_QUAD_CurrentVersionRun_05b8 {
  strings:
    $key_05b8 = { 56 d7 [2] 72 d9 [2] 59 f5 [2] 77 d7 [2] 63 cc [2] 6c d6 [2] 72 cb [2] 70 ca [2] 6b cc [2] 77 cb [2] 6b e4 }

  condition:
    any of them
}