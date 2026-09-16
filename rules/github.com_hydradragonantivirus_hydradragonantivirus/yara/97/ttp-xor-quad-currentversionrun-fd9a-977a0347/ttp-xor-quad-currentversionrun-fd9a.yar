rule TTP_XOR_QUAD_CurrentVersionRun_fd9a {
  strings:
    $key_fd9a = { ae f5 [2] 8a fb [2] a1 d7 [2] 8f f5 [2] 9b ee [2] 94 f4 [2] 8a e9 [2] 88 e8 [2] 93 ee [2] 8f e9 [2] 93 c6 }

  condition:
    any of them
}