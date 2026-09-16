rule TTP_XOR_QUAD_CurrentVersionRun_199a {
  strings:
    $key_199a = { 4a f5 [2] 6e fb [2] 45 d7 [2] 6b f5 [2] 7f ee [2] 70 f4 [2] 6e e9 [2] 6c e8 [2] 77 ee [2] 6b e9 [2] 77 c6 }

  condition:
    any of them
}