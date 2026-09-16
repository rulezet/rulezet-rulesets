rule TTP_XOR_QUAD_CurrentVersionRun_fd97 {
  strings:
    $key_fd97 = { ae f8 [2] 8a f6 [2] a1 da [2] 8f f8 [2] 9b e3 [2] 94 f9 [2] 8a e4 [2] 88 e5 [2] 93 e3 [2] 8f e4 [2] 93 cb }

  condition:
    any of them
}