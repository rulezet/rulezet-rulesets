rule TTP_XOR_QUAD_CurrentVersionRun_109a {
  strings:
    $key_109a = { 43 f5 [2] 67 fb [2] 4c d7 [2] 62 f5 [2] 76 ee [2] 79 f4 [2] 67 e9 [2] 65 e8 [2] 7e ee [2] 62 e9 [2] 7e c6 }

  condition:
    any of them
}