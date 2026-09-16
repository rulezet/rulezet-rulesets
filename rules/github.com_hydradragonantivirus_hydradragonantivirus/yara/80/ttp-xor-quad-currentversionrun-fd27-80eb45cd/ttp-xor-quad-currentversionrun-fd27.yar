rule TTP_XOR_QUAD_CurrentVersionRun_fd27 {
  strings:
    $key_fd27 = { ae 48 [2] 8a 46 [2] a1 6a [2] 8f 48 [2] 9b 53 [2] 94 49 [2] 8a 54 [2] 88 55 [2] 93 53 [2] 8f 54 [2] 93 7b }

  condition:
    any of them
}