rule TTP_XOR_QUAD_CurrentVersionRun_e8b9 {
  strings:
    $key_e8b9 = { bb d6 [2] 9f d8 [2] b4 f4 [2] 9a d6 [2] 8e cd [2] 81 d7 [2] 9f ca [2] 9d cb [2] 86 cd [2] 9a ca [2] 86 e5 }

  condition:
    any of them
}