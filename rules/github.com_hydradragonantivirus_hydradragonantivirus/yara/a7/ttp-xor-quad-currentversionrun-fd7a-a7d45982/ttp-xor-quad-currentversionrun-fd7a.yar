rule TTP_XOR_QUAD_CurrentVersionRun_fd7a {
  strings:
    $key_fd7a = { ae 15 [2] 8a 1b [2] a1 37 [2] 8f 15 [2] 9b 0e [2] 94 14 [2] 8a 09 [2] 88 08 [2] 93 0e [2] 8f 09 [2] 93 26 }

  condition:
    any of them
}