rule TTP_XOR_QUAD_CurrentVersionRun_fd07 {
  strings:
    $key_fd07 = { ae 68 [2] 8a 66 [2] a1 4a [2] 8f 68 [2] 9b 73 [2] 94 69 [2] 8a 74 [2] 88 75 [2] 93 73 [2] 8f 74 [2] 93 5b }

  condition:
    any of them
}