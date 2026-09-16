rule TTP_XOR_QUAD_CurrentVersionRun_349a {
  strings:
    $key_349a = { 67 f5 [2] 43 fb [2] 68 d7 [2] 46 f5 [2] 52 ee [2] 5d f4 [2] 43 e9 [2] 41 e8 [2] 5a ee [2] 46 e9 [2] 5a c6 }

  condition:
    any of them
}