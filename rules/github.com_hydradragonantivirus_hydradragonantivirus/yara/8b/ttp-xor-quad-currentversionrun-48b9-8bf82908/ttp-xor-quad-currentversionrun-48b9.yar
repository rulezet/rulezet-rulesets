rule TTP_XOR_QUAD_CurrentVersionRun_48b9 {
  strings:
    $key_48b9 = { 1b d6 [2] 3f d8 [2] 14 f4 [2] 3a d6 [2] 2e cd [2] 21 d7 [2] 3f ca [2] 3d cb [2] 26 cd [2] 3a ca [2] 26 e5 }

  condition:
    any of them
}