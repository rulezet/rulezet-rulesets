rule TTP_XOR_QUAD_CurrentVersionRun_4db9 {
  strings:
    $key_4db9 = { 1e d6 [2] 3a d8 [2] 11 f4 [2] 3f d6 [2] 2b cd [2] 24 d7 [2] 3a ca [2] 38 cb [2] 23 cd [2] 3f ca [2] 23 e5 }

  condition:
    any of them
}