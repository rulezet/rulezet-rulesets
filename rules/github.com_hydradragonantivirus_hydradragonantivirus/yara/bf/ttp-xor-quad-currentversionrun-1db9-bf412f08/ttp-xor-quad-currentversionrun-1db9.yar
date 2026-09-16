rule TTP_XOR_QUAD_CurrentVersionRun_1db9 {
  strings:
    $key_1db9 = { 4e d6 [2] 6a d8 [2] 41 f4 [2] 6f d6 [2] 7b cd [2] 74 d7 [2] 6a ca [2] 68 cb [2] 73 cd [2] 6f ca [2] 73 e5 }

  condition:
    any of them
}