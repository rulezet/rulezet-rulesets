rule TTP_XOR_QUAD_CurrentVersionRun_fd08 {
  strings:
    $key_fd08 = { ae 67 [2] 8a 69 [2] a1 45 [2] 8f 67 [2] 9b 7c [2] 94 66 [2] 8a 7b [2] 88 7a [2] 93 7c [2] 8f 7b [2] 93 54 }

  condition:
    any of them
}