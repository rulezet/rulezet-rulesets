rule TTP_XOR_QUAD_CurrentVersionRun_e79a {
  strings:
    $key_e79a = { b4 f5 [2] 90 fb [2] bb d7 [2] 95 f5 [2] 81 ee [2] 8e f4 [2] 90 e9 [2] 92 e8 [2] 89 ee [2] 95 e9 [2] 89 c6 }

  condition:
    any of them
}