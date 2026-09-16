rule TTP_XOR_QUAD_CurrentVersionRun_1cb9 {
  strings:
    $key_1cb9 = { 4f d6 [2] 6b d8 [2] 40 f4 [2] 6e d6 [2] 7a cd [2] 75 d7 [2] 6b ca [2] 69 cb [2] 72 cd [2] 6e ca [2] 72 e5 }

  condition:
    any of them
}