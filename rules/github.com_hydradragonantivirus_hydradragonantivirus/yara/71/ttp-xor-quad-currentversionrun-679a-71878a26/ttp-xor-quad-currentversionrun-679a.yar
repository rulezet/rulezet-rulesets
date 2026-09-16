rule TTP_XOR_QUAD_CurrentVersionRun_679a {
  strings:
    $key_679a = { 34 f5 [2] 10 fb [2] 3b d7 [2] 15 f5 [2] 01 ee [2] 0e f4 [2] 10 e9 [2] 12 e8 [2] 09 ee [2] 15 e9 [2] 09 c6 }

  condition:
    any of them
}