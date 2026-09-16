rule TTP_XOR_QUAD_CurrentVersionRun_08b9 {
  strings:
    $key_08b9 = { 5b d6 [2] 7f d8 [2] 54 f4 [2] 7a d6 [2] 6e cd [2] 61 d7 [2] 7f ca [2] 7d cb [2] 66 cd [2] 7a ca [2] 66 e5 }

  condition:
    any of them
}