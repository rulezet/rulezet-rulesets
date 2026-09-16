rule TTP_XOR_QUAD_CurrentVersionRun_7da5 {
  strings:
    $key_7da5 = { 2e ca [2] 0a c4 [2] 21 e8 [2] 0f ca [2] 1b d1 [2] 14 cb [2] 0a d6 [2] 08 d7 [2] 13 d1 [2] 0f d6 [2] 13 f9 }

  condition:
    any of them
}