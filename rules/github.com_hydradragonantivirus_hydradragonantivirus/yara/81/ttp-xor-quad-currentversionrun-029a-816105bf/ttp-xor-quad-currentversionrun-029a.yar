rule TTP_XOR_QUAD_CurrentVersionRun_029a {
  strings:
    $key_029a = { 51 f5 [2] 75 fb [2] 5e d7 [2] 70 f5 [2] 64 ee [2] 6b f4 [2] 75 e9 [2] 77 e8 [2] 6c ee [2] 70 e9 [2] 6c c6 }

  condition:
    any of them
}