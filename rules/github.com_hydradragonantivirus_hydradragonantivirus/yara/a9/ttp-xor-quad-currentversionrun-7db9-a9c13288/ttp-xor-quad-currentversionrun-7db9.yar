rule TTP_XOR_QUAD_CurrentVersionRun_7db9 {
  strings:
    $key_7db9 = { 2e d6 [2] 0a d8 [2] 21 f4 [2] 0f d6 [2] 1b cd [2] 14 d7 [2] 0a ca [2] 08 cb [2] 13 cd [2] 0f ca [2] 13 e5 }

  condition:
    any of them
}