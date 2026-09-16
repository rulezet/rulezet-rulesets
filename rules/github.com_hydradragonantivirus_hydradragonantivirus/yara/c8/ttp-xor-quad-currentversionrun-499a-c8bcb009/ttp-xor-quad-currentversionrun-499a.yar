rule TTP_XOR_QUAD_CurrentVersionRun_499a {
  strings:
    $key_499a = { 1a f5 [2] 3e fb [2] 15 d7 [2] 3b f5 [2] 2f ee [2] 20 f4 [2] 3e e9 [2] 3c e8 [2] 27 ee [2] 3b e9 [2] 27 c6 }

  condition:
    any of them
}