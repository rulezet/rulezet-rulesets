rule TTP_XOR_QUAD_CurrentVersionRun_229a {
  strings:
    $key_229a = { 71 f5 [2] 55 fb [2] 7e d7 [2] 50 f5 [2] 44 ee [2] 4b f4 [2] 55 e9 [2] 57 e8 [2] 4c ee [2] 50 e9 [2] 4c c6 }

  condition:
    any of them
}