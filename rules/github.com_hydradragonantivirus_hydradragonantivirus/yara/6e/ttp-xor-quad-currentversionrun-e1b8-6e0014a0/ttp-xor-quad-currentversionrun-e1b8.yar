rule TTP_XOR_QUAD_CurrentVersionRun_e1b8 {
  strings:
    $key_e1b8 = { b2 d7 [2] 96 d9 [2] bd f5 [2] 93 d7 [2] 87 cc [2] 88 d6 [2] 96 cb [2] 94 ca [2] 8f cc [2] 93 cb [2] 8f e4 }

  condition:
    any of them
}