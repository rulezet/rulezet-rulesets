rule TTP_XOR_QUAD_CurrentVersionRun_f4b8 {
  strings:
    $key_f4b8 = { a7 d7 [2] 83 d9 [2] a8 f5 [2] 86 d7 [2] 92 cc [2] 9d d6 [2] 83 cb [2] 81 ca [2] 9a cc [2] 86 cb [2] 9a e4 }

  condition:
    any of them
}