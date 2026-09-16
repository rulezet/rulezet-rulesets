rule TTP_XOR_QUAD_CurrentVersionRun_2d8a {
  strings:
    $key_2d8a = { 7e e5 [2] 5a eb [2] 71 c7 [2] 5f e5 [2] 4b fe [2] 44 e4 [2] 5a f9 [2] 58 f8 [2] 43 fe [2] 5f f9 [2] 43 d6 }

  condition:
    any of them
}