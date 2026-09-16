rule TTP_XOR_QUAD_CurrentVersionRun_fd60 {
  strings:
    $key_fd60 = { ae 0f [2] 8a 01 [2] a1 2d [2] 8f 0f [2] 9b 14 [2] 94 0e [2] 8a 13 [2] 88 12 [2] 93 14 [2] 8f 13 [2] 93 3c }

  condition:
    any of them
}