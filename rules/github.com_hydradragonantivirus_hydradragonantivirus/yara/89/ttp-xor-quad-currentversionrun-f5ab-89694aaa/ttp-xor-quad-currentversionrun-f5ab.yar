rule TTP_XOR_QUAD_CurrentVersionRun_f5ab {
  strings:
    $key_f5ab = { a6 c4 [2] 82 ca [2] a9 e6 [2] 87 c4 [2] 93 df [2] 9c c5 [2] 82 d8 [2] 80 d9 [2] 9b df [2] 87 d8 [2] 9b f7 }

  condition:
    any of them
}