rule TTP_XOR_QUAD_CurrentVersionRun_3d8a {
  strings:
    $key_3d8a = { 6e e5 [2] 4a eb [2] 61 c7 [2] 4f e5 [2] 5b fe [2] 54 e4 [2] 4a f9 [2] 48 f8 [2] 53 fe [2] 4f f9 [2] 53 d6 }

  condition:
    any of them
}