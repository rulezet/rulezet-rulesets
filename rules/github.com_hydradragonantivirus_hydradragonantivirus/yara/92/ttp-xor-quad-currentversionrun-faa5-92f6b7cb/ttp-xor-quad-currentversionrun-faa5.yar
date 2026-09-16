rule TTP_XOR_QUAD_CurrentVersionRun_faa5 {
  strings:
    $key_faa5 = { a9 ca [2] 8d c4 [2] a6 e8 [2] 88 ca [2] 9c d1 [2] 93 cb [2] 8d d6 [2] 8f d7 [2] 94 d1 [2] 88 d6 [2] 94 f9 }

  condition:
    any of them
}