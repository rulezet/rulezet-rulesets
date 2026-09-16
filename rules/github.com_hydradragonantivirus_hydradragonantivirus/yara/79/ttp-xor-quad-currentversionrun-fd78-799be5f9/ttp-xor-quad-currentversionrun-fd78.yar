rule TTP_XOR_QUAD_CurrentVersionRun_fd78 {
  strings:
    $key_fd78 = { ae 17 [2] 8a 19 [2] a1 35 [2] 8f 17 [2] 9b 0c [2] 94 16 [2] 8a 0b [2] 88 0a [2] 93 0c [2] 8f 0b [2] 93 24 }

  condition:
    any of them
}