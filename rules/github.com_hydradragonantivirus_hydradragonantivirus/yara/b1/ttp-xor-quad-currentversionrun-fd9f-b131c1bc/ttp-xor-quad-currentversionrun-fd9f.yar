rule TTP_XOR_QUAD_CurrentVersionRun_fd9f {
  strings:
    $key_fd9f = { ae f0 [2] 8a fe [2] a1 d2 [2] 8f f0 [2] 9b eb [2] 94 f1 [2] 8a ec [2] 88 ed [2] 93 eb [2] 8f ec [2] 93 c3 }

  condition:
    any of them
}