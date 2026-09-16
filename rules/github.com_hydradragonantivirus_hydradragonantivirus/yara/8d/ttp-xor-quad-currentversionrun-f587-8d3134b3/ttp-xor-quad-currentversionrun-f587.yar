rule TTP_XOR_QUAD_CurrentVersionRun_f587 {
  strings:
    $key_f587 = { a6 e8 [2] 82 e6 [2] a9 ca [2] 87 e8 [2] 93 f3 [2] 9c e9 [2] 82 f4 [2] 80 f5 [2] 9b f3 [2] 87 f4 [2] 9b db }

  condition:
    any of them
}