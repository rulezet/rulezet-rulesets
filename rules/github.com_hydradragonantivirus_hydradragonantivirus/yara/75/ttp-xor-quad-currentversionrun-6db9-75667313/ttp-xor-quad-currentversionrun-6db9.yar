rule TTP_XOR_QUAD_CurrentVersionRun_6db9 {
  strings:
    $key_6db9 = { 3e d6 [2] 1a d8 [2] 31 f4 [2] 1f d6 [2] 0b cd [2] 04 d7 [2] 1a ca [2] 18 cb [2] 03 cd [2] 1f ca [2] 03 e5 }

  condition:
    any of them
}