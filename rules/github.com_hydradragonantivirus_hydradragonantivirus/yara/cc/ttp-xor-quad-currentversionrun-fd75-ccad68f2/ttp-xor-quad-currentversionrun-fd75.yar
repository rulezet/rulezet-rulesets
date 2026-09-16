rule TTP_XOR_QUAD_CurrentVersionRun_fd75 {
  strings:
    $key_fd75 = { ae 1a [2] 8a 14 [2] a1 38 [2] 8f 1a [2] 9b 01 [2] 94 1b [2] 8a 06 [2] 88 07 [2] 93 01 [2] 8f 06 [2] 93 29 }

  condition:
    any of them
}