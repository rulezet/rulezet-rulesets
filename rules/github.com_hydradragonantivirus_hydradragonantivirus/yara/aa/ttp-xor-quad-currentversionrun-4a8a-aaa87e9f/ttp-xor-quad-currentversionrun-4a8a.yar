rule TTP_XOR_QUAD_CurrentVersionRun_4a8a {
  strings:
    $key_4a8a = { 19 e5 [2] 3d eb [2] 16 c7 [2] 38 e5 [2] 2c fe [2] 23 e4 [2] 3d f9 [2] 3f f8 [2] 24 fe [2] 38 f9 [2] 24 d6 }

  condition:
    any of them
}