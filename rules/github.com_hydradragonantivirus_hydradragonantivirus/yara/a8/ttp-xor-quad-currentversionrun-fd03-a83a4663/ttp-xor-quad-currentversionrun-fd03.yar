rule TTP_XOR_QUAD_CurrentVersionRun_fd03 {
  strings:
    $key_fd03 = { ae 6c [2] 8a 62 [2] a1 4e [2] 8f 6c [2] 9b 77 [2] 94 6d [2] 8a 70 [2] 88 71 [2] 93 77 [2] 8f 70 [2] 93 5f }

  condition:
    any of them
}