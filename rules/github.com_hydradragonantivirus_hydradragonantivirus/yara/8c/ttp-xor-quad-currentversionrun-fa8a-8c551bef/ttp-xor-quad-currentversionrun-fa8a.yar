rule TTP_XOR_QUAD_CurrentVersionRun_fa8a {
  strings:
    $key_fa8a = { a9 e5 [2] 8d eb [2] a6 c7 [2] 88 e5 [2] 9c fe [2] 93 e4 [2] 8d f9 [2] 8f f8 [2] 94 fe [2] 88 f9 [2] 94 d6 }

  condition:
    any of them
}