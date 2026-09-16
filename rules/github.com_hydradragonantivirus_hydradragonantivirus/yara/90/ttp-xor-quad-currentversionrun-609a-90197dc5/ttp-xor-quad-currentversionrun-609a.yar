rule TTP_XOR_QUAD_CurrentVersionRun_609a {
  strings:
    $key_609a = { 33 f5 [2] 17 fb [2] 3c d7 [2] 12 f5 [2] 06 ee [2] 09 f4 [2] 17 e9 [2] 15 e8 [2] 0e ee [2] 12 e9 [2] 0e c6 }

  condition:
    any of them
}