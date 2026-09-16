rule TTP_XOR_QUAD_CurrentVersionRun_2db9 {
  strings:
    $key_2db9 = { 7e d6 [2] 5a d8 [2] 71 f4 [2] 5f d6 [2] 4b cd [2] 44 d7 [2] 5a ca [2] 58 cb [2] 43 cd [2] 5f ca [2] 43 e5 }

  condition:
    any of them
}