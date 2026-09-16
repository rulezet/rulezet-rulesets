rule TTP_XOR_QUAD_CurrentVersionRun_58b9 {
  strings:
    $key_58b9 = { 0b d6 [2] 2f d8 [2] 04 f4 [2] 2a d6 [2] 3e cd [2] 31 d7 [2] 2f ca [2] 2d cb [2] 36 cd [2] 2a ca [2] 36 e5 }

  condition:
    any of them
}