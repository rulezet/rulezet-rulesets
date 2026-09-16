rule TTP_XOR_QUAD_CurrentVersionRun_fd36 {
  strings:
    $key_fd36 = { ae 59 [2] 8a 57 [2] a1 7b [2] 8f 59 [2] 9b 42 [2] 94 58 [2] 8a 45 [2] 88 44 [2] 93 42 [2] 8f 45 [2] 93 6a }

  condition:
    any of them
}