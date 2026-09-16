rule TTP_XOR_QUAD_CurrentVersionRun_fd50 {
  strings:
    $key_fd50 = { ae 3f [2] 8a 31 [2] a1 1d [2] 8f 3f [2] 9b 24 [2] 94 3e [2] 8a 23 [2] 88 22 [2] 93 24 [2] 8f 23 [2] 93 0c }

  condition:
    any of them
}