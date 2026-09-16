rule TTP_XOR_QUAD_CurrentVersionRun_f1b8 {
  strings:
    $key_f1b8 = { a2 d7 [2] 86 d9 [2] ad f5 [2] 83 d7 [2] 97 cc [2] 98 d6 [2] 86 cb [2] 84 ca [2] 9f cc [2] 83 cb [2] 9f e4 }

  condition:
    any of them
}