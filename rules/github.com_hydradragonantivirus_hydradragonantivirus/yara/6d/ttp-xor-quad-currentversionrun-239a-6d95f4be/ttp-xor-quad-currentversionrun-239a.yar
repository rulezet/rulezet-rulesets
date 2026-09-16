rule TTP_XOR_QUAD_CurrentVersionRun_239a {
  strings:
    $key_239a = { 70 f5 [2] 54 fb [2] 7f d7 [2] 51 f5 [2] 45 ee [2] 4a f4 [2] 54 e9 [2] 56 e8 [2] 4d ee [2] 51 e9 [2] 4d c6 }

  condition:
    any of them
}