rule TTP_XOR_QUAD_CurrentVersionRun_38b9 {
  strings:
    $key_38b9 = { 6b d6 [2] 4f d8 [2] 64 f4 [2] 4a d6 [2] 5e cd [2] 51 d7 [2] 4f ca [2] 4d cb [2] 56 cd [2] 4a ca [2] 56 e5 }

  condition:
    any of them
}