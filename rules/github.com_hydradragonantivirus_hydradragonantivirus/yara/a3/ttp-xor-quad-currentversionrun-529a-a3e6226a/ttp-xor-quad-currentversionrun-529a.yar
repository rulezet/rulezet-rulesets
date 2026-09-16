rule TTP_XOR_QUAD_CurrentVersionRun_529a {
  strings:
    $key_529a = { 01 f5 [2] 25 fb [2] 0e d7 [2] 20 f5 [2] 34 ee [2] 3b f4 [2] 25 e9 [2] 27 e8 [2] 3c ee [2] 20 e9 [2] 3c c6 }

  condition:
    any of them
}