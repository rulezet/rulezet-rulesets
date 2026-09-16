rule TTP_XOR_QUAD_CurrentVersionRun_fd62 {
  strings:
    $key_fd62 = { ae 0d [2] 8a 03 [2] a1 2f [2] 8f 0d [2] 9b 16 [2] 94 0c [2] 8a 11 [2] 88 10 [2] 93 16 [2] 8f 11 [2] 93 3e }

  condition:
    any of them
}