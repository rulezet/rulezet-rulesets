rule TTP_XOR_QUAD_CurrentVersionRun_5cb9 {
  strings:
    $key_5cb9 = { 0f d6 [2] 2b d8 [2] 00 f4 [2] 2e d6 [2] 3a cd [2] 35 d7 [2] 2b ca [2] 29 cb [2] 32 cd [2] 2e ca [2] 32 e5 }

  condition:
    any of them
}