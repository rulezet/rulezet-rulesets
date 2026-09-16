rule TTP_XOR_QUAD_CurrentVersionRun_f8b9 {
  strings:
    $key_f8b9 = { ab d6 [2] 8f d8 [2] a4 f4 [2] 8a d6 [2] 9e cd [2] 91 d7 [2] 8f ca [2] 8d cb [2] 96 cd [2] 8a ca [2] 96 e5 }

  condition:
    any of them
}