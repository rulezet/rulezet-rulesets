rule TTP_XOR_QUAD_CurrentVersionRun_288a {
  strings:
    $key_288a = { 7b e5 [2] 5f eb [2] 74 c7 [2] 5a e5 [2] 4e fe [2] 41 e4 [2] 5f f9 [2] 5d f8 [2] 46 fe [2] 5a f9 [2] 46 d6 }

  condition:
    any of them
}