rule TTP_XOR_QUAD_CurrentVersionRun_fd9e {
  strings:
    $key_fd9e = { ae f1 [2] 8a ff [2] a1 d3 [2] 8f f1 [2] 9b ea [2] 94 f0 [2] 8a ed [2] 88 ec [2] 93 ea [2] 8f ed [2] 93 c2 }

  condition:
    any of them
}