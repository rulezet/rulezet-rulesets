rule TTP_XOR_QUAD_CurrentVersionRun_fd56 {
  strings:
    $key_fd56 = { ae 39 [2] 8a 37 [2] a1 1b [2] 8f 39 [2] 9b 22 [2] 94 38 [2] 8a 25 [2] 88 24 [2] 93 22 [2] 8f 25 [2] 93 0a }

  condition:
    any of them
}