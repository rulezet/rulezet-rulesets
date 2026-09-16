rule TTP_XOR_QUAD_CurrentVersionRun_6cb9 {
  strings:
    $key_6cb9 = { 3f d6 [2] 1b d8 [2] 30 f4 [2] 1e d6 [2] 0a cd [2] 05 d7 [2] 1b ca [2] 19 cb [2] 02 cd [2] 1e ca [2] 02 e5 }

  condition:
    any of them
}