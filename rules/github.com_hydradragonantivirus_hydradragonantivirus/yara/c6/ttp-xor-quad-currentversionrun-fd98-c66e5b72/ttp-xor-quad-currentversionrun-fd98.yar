rule TTP_XOR_QUAD_CurrentVersionRun_fd98 {
  strings:
    $key_fd98 = { ae f7 [2] 8a f9 [2] a1 d5 [2] 8f f7 [2] 9b ec [2] 94 f6 [2] 8a eb [2] 88 ea [2] 93 ec [2] 8f eb [2] 93 c4 }

  condition:
    any of them
}