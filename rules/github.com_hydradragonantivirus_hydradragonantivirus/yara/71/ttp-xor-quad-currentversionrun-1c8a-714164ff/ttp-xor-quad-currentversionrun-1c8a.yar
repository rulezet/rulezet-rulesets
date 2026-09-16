rule TTP_XOR_QUAD_CurrentVersionRun_1c8a {
  strings:
    $key_1c8a = { 4f e5 [2] 6b eb [2] 40 c7 [2] 6e e5 [2] 7a fe [2] 75 e4 [2] 6b f9 [2] 69 f8 [2] 72 fe [2] 6e f9 [2] 72 d6 }

  condition:
    any of them
}