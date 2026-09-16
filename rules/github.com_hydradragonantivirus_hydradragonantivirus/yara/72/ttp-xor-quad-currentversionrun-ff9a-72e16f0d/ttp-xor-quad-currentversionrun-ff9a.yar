rule TTP_XOR_QUAD_CurrentVersionRun_ff9a {
  strings:
    $key_ff9a = { ac f5 [2] 88 fb [2] a3 d7 [2] 8d f5 [2] 99 ee [2] 96 f4 [2] 88 e9 [2] 8a e8 [2] 91 ee [2] 8d e9 [2] 91 c6 }

  condition:
    any of them
}