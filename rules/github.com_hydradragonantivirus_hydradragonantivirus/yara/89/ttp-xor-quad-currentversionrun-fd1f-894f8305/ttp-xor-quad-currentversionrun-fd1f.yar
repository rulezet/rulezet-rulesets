rule TTP_XOR_QUAD_CurrentVersionRun_fd1f {
  strings:
    $key_fd1f = { ae 70 [2] 8a 7e [2] a1 52 [2] 8f 70 [2] 9b 6b [2] 94 71 [2] 8a 6c [2] 88 6d [2] 93 6b [2] 8f 6c [2] 93 43 }

  condition:
    any of them
}