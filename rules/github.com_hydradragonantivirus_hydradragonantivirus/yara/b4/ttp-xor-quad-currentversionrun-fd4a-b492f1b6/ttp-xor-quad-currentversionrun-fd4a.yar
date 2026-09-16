rule TTP_XOR_QUAD_CurrentVersionRun_fd4a {
  strings:
    $key_fd4a = { ae 25 [2] 8a 2b [2] a1 07 [2] 8f 25 [2] 9b 3e [2] 94 24 [2] 8a 39 [2] 88 38 [2] 93 3e [2] 8f 39 [2] 93 16 }

  condition:
    any of them
}