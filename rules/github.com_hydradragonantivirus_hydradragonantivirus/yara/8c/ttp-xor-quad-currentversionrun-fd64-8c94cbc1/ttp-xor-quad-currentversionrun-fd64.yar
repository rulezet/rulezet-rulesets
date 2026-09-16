rule TTP_XOR_QUAD_CurrentVersionRun_fd64 {
  strings:
    $key_fd64 = { ae 0b [2] 8a 05 [2] a1 29 [2] 8f 0b [2] 9b 10 [2] 94 0a [2] 8a 17 [2] 88 16 [2] 93 10 [2] 8f 17 [2] 93 38 }

  condition:
    any of them
}