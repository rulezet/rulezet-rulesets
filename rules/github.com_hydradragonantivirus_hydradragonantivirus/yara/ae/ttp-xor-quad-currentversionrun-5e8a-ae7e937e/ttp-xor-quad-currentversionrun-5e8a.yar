rule TTP_XOR_QUAD_CurrentVersionRun_5e8a {
  strings:
    $key_5e8a = { 0d e5 [2] 29 eb [2] 02 c7 [2] 2c e5 [2] 38 fe [2] 37 e4 [2] 29 f9 [2] 2b f8 [2] 30 fe [2] 2c f9 [2] 30 d6 }

  condition:
    any of them
}