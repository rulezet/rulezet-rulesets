rule TTP_XOR_QUAD_CurrentVersionRun_71b8 {
  strings:
    $key_71b8 = { 22 d7 [2] 06 d9 [2] 2d f5 [2] 03 d7 [2] 17 cc [2] 18 d6 [2] 06 cb [2] 04 ca [2] 1f cc [2] 03 cb [2] 1f e4 }

  condition:
    any of them
}