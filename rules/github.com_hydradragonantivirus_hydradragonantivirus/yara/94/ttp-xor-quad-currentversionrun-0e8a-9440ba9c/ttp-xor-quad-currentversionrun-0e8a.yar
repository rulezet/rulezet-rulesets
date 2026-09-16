rule TTP_XOR_QUAD_CurrentVersionRun_0e8a {
  strings:
    $key_0e8a = { 5d e5 [2] 79 eb [2] 52 c7 [2] 7c e5 [2] 68 fe [2] 67 e4 [2] 79 f9 [2] 7b f8 [2] 60 fe [2] 7c f9 [2] 60 d6 }

  condition:
    any of them
}