rule TTP_XOR_QUAD_CurrentVersionRun_329a {
  strings:
    $key_329a = { 61 f5 [2] 45 fb [2] 6e d7 [2] 40 f5 [2] 54 ee [2] 5b f4 [2] 45 e9 [2] 47 e8 [2] 5c ee [2] 40 e9 [2] 5c c6 }

  condition:
    any of them
}