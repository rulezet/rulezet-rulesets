rule TTP_XOR_QUAD_CurrentVersionRun_1e8a {
  strings:
    $key_1e8a = { 4d e5 [2] 69 eb [2] 42 c7 [2] 6c e5 [2] 78 fe [2] 77 e4 [2] 69 f9 [2] 6b f8 [2] 70 fe [2] 6c f9 [2] 70 d6 }

  condition:
    any of them
}