rule TTP_XOR_QUAD_CurrentVersionRun_f79a {
  strings:
    $key_f79a = { a4 f5 [2] 80 fb [2] ab d7 [2] 85 f5 [2] 91 ee [2] 9e f4 [2] 80 e9 [2] 82 e8 [2] 99 ee [2] 85 e9 [2] 99 c6 }

  condition:
    any of them
}