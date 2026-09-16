rule TTP_XOR_QUAD_CurrentVersionRun_5c8a {
  strings:
    $key_5c8a = { 0f e5 [2] 2b eb [2] 00 c7 [2] 2e e5 [2] 3a fe [2] 35 e4 [2] 2b f9 [2] 29 f8 [2] 32 fe [2] 2e f9 [2] 32 d6 }

  condition:
    any of them
}