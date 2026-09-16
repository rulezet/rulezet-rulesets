rule TTP_XOR_QUAD_CurrentVersionRun_fd74 {
  strings:
    $key_fd74 = { ae 1b [2] 8a 15 [2] a1 39 [2] 8f 1b [2] 9b 00 [2] 94 1a [2] 8a 07 [2] 88 06 [2] 93 00 [2] 8f 07 [2] 93 28 }

  condition:
    any of them
}