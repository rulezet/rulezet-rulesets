rule TTP_XOR_QUAD_CurrentVersionRun_0a8a {
  strings:
    $key_0a8a = { 59 e5 [2] 7d eb [2] 56 c7 [2] 78 e5 [2] 6c fe [2] 63 e4 [2] 7d f9 [2] 7f f8 [2] 64 fe [2] 78 f9 [2] 64 d6 }

  condition:
    any of them
}