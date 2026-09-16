rule TTP_XOR_QUAD_CurrentVersionRun_fd15 {
  strings:
    $key_fd15 = { ae 7a [2] 8a 74 [2] a1 58 [2] 8f 7a [2] 9b 61 [2] 94 7b [2] 8a 66 [2] 88 67 [2] 93 61 [2] 8f 66 [2] 93 49 }

  condition:
    any of them
}