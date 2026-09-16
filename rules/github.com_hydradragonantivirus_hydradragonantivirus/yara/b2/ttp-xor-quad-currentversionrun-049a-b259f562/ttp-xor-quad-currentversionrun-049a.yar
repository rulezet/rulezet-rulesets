rule TTP_XOR_QUAD_CurrentVersionRun_049a {
  strings:
    $key_049a = { 57 f5 [2] 73 fb [2] 58 d7 [2] 76 f5 [2] 62 ee [2] 6d f4 [2] 73 e9 [2] 71 e8 [2] 6a ee [2] 76 e9 [2] 6a c6 }

  condition:
    any of them
}