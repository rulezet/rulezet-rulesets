rule TTP_XOR_QUAD_CurrentVersionRun_129a {
  strings:
    $key_129a = { 41 f5 [2] 65 fb [2] 4e d7 [2] 60 f5 [2] 74 ee [2] 7b f4 [2] 65 e9 [2] 67 e8 [2] 7c ee [2] 60 e9 [2] 7c c6 }

  condition:
    any of them
}