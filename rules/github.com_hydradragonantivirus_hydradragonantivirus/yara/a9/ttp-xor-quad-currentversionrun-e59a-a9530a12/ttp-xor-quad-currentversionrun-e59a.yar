rule TTP_XOR_QUAD_CurrentVersionRun_e59a {
  strings:
    $key_e59a = { b6 f5 [2] 92 fb [2] b9 d7 [2] 97 f5 [2] 83 ee [2] 8c f4 [2] 92 e9 [2] 90 e8 [2] 8b ee [2] 97 e9 [2] 8b c6 }

  condition:
    any of them
}