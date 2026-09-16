rule TTP_XOR_QUAD_CurrentVersionRun_fd5b {
  strings:
    $key_fd5b = { ae 34 [2] 8a 3a [2] a1 16 [2] 8f 34 [2] 9b 2f [2] 94 35 [2] 8a 28 [2] 88 29 [2] 93 2f [2] 8f 28 [2] 93 07 }

  condition:
    any of them
}