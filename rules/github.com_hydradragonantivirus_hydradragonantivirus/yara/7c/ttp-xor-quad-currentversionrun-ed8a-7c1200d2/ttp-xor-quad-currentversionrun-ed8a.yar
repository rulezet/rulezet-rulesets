rule TTP_XOR_QUAD_CurrentVersionRun_ed8a {
  strings:
    $key_ed8a = { be e5 [2] 9a eb [2] b1 c7 [2] 9f e5 [2] 8b fe [2] 84 e4 [2] 9a f9 [2] 98 f8 [2] 83 fe [2] 9f f9 [2] 83 d6 }

  condition:
    any of them
}