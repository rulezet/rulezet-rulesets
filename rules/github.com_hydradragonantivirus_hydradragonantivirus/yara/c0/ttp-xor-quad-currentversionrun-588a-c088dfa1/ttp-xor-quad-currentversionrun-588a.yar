rule TTP_XOR_QUAD_CurrentVersionRun_588a {
  strings:
    $key_588a = { 0b e5 [2] 2f eb [2] 04 c7 [2] 2a e5 [2] 3e fe [2] 31 e4 [2] 2f f9 [2] 2d f8 [2] 36 fe [2] 2a f9 [2] 36 d6 }

  condition:
    any of them
}