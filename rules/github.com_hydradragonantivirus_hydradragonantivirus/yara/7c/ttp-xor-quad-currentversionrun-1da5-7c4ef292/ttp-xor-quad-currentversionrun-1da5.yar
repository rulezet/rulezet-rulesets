rule TTP_XOR_QUAD_CurrentVersionRun_1da5 {
  strings:
    $key_1da5 = { 4e ca [2] 6a c4 [2] 41 e8 [2] 6f ca [2] 7b d1 [2] 74 cb [2] 6a d6 [2] 68 d7 [2] 73 d1 [2] 6f d6 [2] 73 f9 }

  condition:
    any of them
}