rule TTP_XOR_QUAD_CurrentVersionRun_fd58 {
  strings:
    $key_fd58 = { ae 37 [2] 8a 39 [2] a1 15 [2] 8f 37 [2] 9b 2c [2] 94 36 [2] 8a 2b [2] 88 2a [2] 93 2c [2] 8f 2b [2] 93 04 }

  condition:
    any of them
}