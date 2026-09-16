rule TTP_XOR_QUAD_CurrentVersionRun_079a {
  strings:
    $key_079a = { 54 f5 [2] 70 fb [2] 5b d7 [2] 75 f5 [2] 61 ee [2] 6e f4 [2] 70 e9 [2] 72 e8 [2] 69 ee [2] 75 e9 [2] 69 c6 }

  condition:
    any of them
}