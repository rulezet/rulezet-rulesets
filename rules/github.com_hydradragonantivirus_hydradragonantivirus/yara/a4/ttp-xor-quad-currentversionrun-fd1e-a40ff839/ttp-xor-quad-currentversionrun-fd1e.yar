rule TTP_XOR_QUAD_CurrentVersionRun_fd1e {
  strings:
    $key_fd1e = { ae 71 [2] 8a 7f [2] a1 53 [2] 8f 71 [2] 9b 6a [2] 94 70 [2] 8a 6d [2] 88 6c [2] 93 6a [2] 8f 6d [2] 93 42 }

  condition:
    any of them
}