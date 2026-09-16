rule TTP_XOR_QUAD_CurrentVersionRun_fd7b {
  strings:
    $key_fd7b = { ae 14 [2] 8a 1a [2] a1 36 [2] 8f 14 [2] 9b 0f [2] 94 15 [2] 8a 08 [2] 88 09 [2] 93 0f [2] 8f 08 [2] 93 27 }

  condition:
    any of them
}