rule TTP_XOR_QUAD_CurrentVersionRun_fd7e {
  strings:
    $key_fd7e = { ae 11 [2] 8a 1f [2] a1 33 [2] 8f 11 [2] 9b 0a [2] 94 10 [2] 8a 0d [2] 88 0c [2] 93 0a [2] 8f 0d [2] 93 22 }

  condition:
    any of them
}