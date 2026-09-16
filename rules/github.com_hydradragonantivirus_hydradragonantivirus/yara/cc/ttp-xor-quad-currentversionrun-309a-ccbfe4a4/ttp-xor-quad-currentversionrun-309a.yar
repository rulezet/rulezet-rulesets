rule TTP_XOR_QUAD_CurrentVersionRun_309a {
  strings:
    $key_309a = { 63 f5 [2] 47 fb [2] 6c d7 [2] 42 f5 [2] 56 ee [2] 59 f4 [2] 47 e9 [2] 45 e8 [2] 5e ee [2] 42 e9 [2] 5e c6 }

  condition:
    any of them
}