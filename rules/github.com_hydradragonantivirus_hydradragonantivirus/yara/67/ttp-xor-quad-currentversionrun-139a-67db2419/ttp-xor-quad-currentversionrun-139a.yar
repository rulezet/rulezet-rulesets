rule TTP_XOR_QUAD_CurrentVersionRun_139a {
  strings:
    $key_139a = { 40 f5 [2] 64 fb [2] 4f d7 [2] 61 f5 [2] 75 ee [2] 7a f4 [2] 64 e9 [2] 66 e8 [2] 7d ee [2] 61 e9 [2] 7d c6 }

  condition:
    any of them
}