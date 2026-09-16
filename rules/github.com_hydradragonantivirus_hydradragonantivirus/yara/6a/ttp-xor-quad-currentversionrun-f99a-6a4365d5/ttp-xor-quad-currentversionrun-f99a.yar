rule TTP_XOR_QUAD_CurrentVersionRun_f99a {
  strings:
    $key_f99a = { aa f5 [2] 8e fb [2] a5 d7 [2] 8b f5 [2] 9f ee [2] 90 f4 [2] 8e e9 [2] 8c e8 [2] 97 ee [2] 8b e9 [2] 97 c6 }

  condition:
    any of them
}