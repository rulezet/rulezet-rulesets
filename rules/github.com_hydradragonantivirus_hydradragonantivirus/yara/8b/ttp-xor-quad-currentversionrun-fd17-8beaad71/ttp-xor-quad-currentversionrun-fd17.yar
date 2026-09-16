rule TTP_XOR_QUAD_CurrentVersionRun_fd17 {
  strings:
    $key_fd17 = { ae 78 [2] 8a 76 [2] a1 5a [2] 8f 78 [2] 9b 63 [2] 94 79 [2] 8a 64 [2] 88 65 [2] 93 63 [2] 8f 64 [2] 93 4b }

  condition:
    any of them
}