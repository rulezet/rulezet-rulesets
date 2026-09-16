rule TTP_XOR_QUAD_CurrentVersionRun_1f8a {
  strings:
    $key_1f8a = { 4c e5 [2] 68 eb [2] 43 c7 [2] 6d e5 [2] 79 fe [2] 76 e4 [2] 68 f9 [2] 6a f8 [2] 71 fe [2] 6d f9 [2] 71 d6 }

  condition:
    any of them
}