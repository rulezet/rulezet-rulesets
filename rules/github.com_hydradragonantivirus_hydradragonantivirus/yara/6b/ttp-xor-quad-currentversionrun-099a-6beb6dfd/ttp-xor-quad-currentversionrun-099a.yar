rule TTP_XOR_QUAD_CurrentVersionRun_099a {
  strings:
    $key_099a = { 5a f5 [2] 7e fb [2] 55 d7 [2] 7b f5 [2] 6f ee [2] 60 f4 [2] 7e e9 [2] 7c e8 [2] 67 ee [2] 7b e9 [2] 67 c6 }

  condition:
    any of them
}