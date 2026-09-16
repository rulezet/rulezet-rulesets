rule TTP_XOR_QUAD_CurrentVersionRun_f99d {
  strings:
    $key_f99d = { aa f2 [2] 8e fc [2] a5 d0 [2] 8b f2 [2] 9f e9 [2] 90 f3 [2] 8e ee [2] 8c ef [2] 97 e9 [2] 8b ee [2] 97 c1 }

  condition:
    any of them
}