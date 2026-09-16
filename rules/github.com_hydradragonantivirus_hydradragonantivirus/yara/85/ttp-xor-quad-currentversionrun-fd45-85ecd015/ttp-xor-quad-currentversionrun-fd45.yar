rule TTP_XOR_QUAD_CurrentVersionRun_fd45 {
  strings:
    $key_fd45 = { ae 2a [2] 8a 24 [2] a1 08 [2] 8f 2a [2] 9b 31 [2] 94 2b [2] 8a 36 [2] 88 37 [2] 93 31 [2] 8f 36 [2] 93 19 }

  condition:
    any of them
}