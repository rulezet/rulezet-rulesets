rule TTP_XOR_QUAD_CurrentVersionRun_faa4 {
  strings:
    $key_faa4 = { a9 cb [2] 8d c5 [2] a6 e9 [2] 88 cb [2] 9c d0 [2] 93 ca [2] 8d d7 [2] 8f d6 [2] 94 d0 [2] 88 d7 [2] 94 f8 }

  condition:
    any of them
}