rule TTP_XOR_QUAD_CurrentVersionRun_3cb9 {
  strings:
    $key_3cb9 = { 6f d6 [2] 4b d8 [2] 60 f4 [2] 4e d6 [2] 5a cd [2] 55 d7 [2] 4b ca [2] 49 cb [2] 52 cd [2] 4e ca [2] 52 e5 }

  condition:
    any of them
}