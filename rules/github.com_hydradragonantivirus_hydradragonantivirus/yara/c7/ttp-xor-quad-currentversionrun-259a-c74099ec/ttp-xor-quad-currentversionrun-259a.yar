rule TTP_XOR_QUAD_CurrentVersionRun_259a {
  strings:
    $key_259a = { 76 f5 [2] 52 fb [2] 79 d7 [2] 57 f5 [2] 43 ee [2] 4c f4 [2] 52 e9 [2] 50 e8 [2] 4b ee [2] 57 e9 [2] 4b c6 }

  condition:
    any of them
}