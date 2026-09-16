rule TTP_XOR_QUAD_CurrentVersionRun_fd5a {
  strings:
    $key_fd5a = { ae 35 [2] 8a 3b [2] a1 17 [2] 8f 35 [2] 9b 2e [2] 94 34 [2] 8a 29 [2] 88 28 [2] 93 2e [2] 8f 29 [2] 93 06 }

  condition:
    any of them
}