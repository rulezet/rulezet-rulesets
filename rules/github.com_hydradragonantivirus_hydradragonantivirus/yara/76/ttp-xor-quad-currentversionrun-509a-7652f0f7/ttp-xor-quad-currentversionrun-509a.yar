rule TTP_XOR_QUAD_CurrentVersionRun_509a {
  strings:
    $key_509a = { 03 f5 [2] 27 fb [2] 0c d7 [2] 22 f5 [2] 36 ee [2] 39 f4 [2] 27 e9 [2] 25 e8 [2] 3e ee [2] 22 e9 [2] 3e c6 }

  condition:
    any of them
}