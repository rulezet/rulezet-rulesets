rule TTP_XOR_QUAD_CurrentVersionRun_7cb9 {
  strings:
    $key_7cb9 = { 2f d6 [2] 0b d8 [2] 20 f4 [2] 0e d6 [2] 1a cd [2] 15 d7 [2] 0b ca [2] 09 cb [2] 12 cd [2] 0e ca [2] 12 e5 }

  condition:
    any of them
}