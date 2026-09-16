rule TTP_XOR_QUAD_CurrentVersionRun_fd7c {
  strings:
    $key_fd7c = { ae 13 [2] 8a 1d [2] a1 31 [2] 8f 13 [2] 9b 08 [2] 94 12 [2] 8a 0f [2] 88 0e [2] 93 08 [2] 8f 0f [2] 93 20 }

  condition:
    any of them
}