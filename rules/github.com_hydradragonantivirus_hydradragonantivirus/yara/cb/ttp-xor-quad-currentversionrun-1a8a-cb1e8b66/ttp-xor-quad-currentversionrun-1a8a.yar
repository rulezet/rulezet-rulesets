rule TTP_XOR_QUAD_CurrentVersionRun_1a8a {
  strings:
    $key_1a8a = { 49 e5 [2] 6d eb [2] 46 c7 [2] 68 e5 [2] 7c fe [2] 73 e4 [2] 6d f9 [2] 6f f8 [2] 74 fe [2] 68 f9 [2] 74 d6 }

  condition:
    any of them
}