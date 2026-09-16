rule TTP_XOR_QUAD_CurrentVersionRun_fd8a {
  strings:
    $key_fd8a = { ae e5 [2] 8a eb [2] a1 c7 [2] 8f e5 [2] 9b fe [2] 94 e4 [2] 8a f9 [2] 88 f8 [2] 93 fe [2] 8f f9 [2] 93 d6 }

  condition:
    any of them
}