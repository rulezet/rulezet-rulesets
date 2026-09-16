rule TTP_XOR_QUAD_CurrentVersionRun_fd1a {
  strings:
    $key_fd1a = { ae 75 [2] 8a 7b [2] a1 57 [2] 8f 75 [2] 9b 6e [2] 94 74 [2] 8a 69 [2] 88 68 [2] 93 6e [2] 8f 69 [2] 93 46 }

  condition:
    any of them
}