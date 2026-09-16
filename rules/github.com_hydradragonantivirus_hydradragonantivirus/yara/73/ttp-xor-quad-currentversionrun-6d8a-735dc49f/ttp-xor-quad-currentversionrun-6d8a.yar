rule TTP_XOR_QUAD_CurrentVersionRun_6d8a {
  strings:
    $key_6d8a = { 3e e5 [2] 1a eb [2] 31 c7 [2] 1f e5 [2] 0b fe [2] 04 e4 [2] 1a f9 [2] 18 f8 [2] 03 fe [2] 1f f9 [2] 03 d6 }

  condition:
    any of them
}