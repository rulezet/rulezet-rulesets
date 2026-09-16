rule TTP_XOR_QUAD_CurrentVersionRun_fd20 {
  strings:
    $key_fd20 = { ae 4f [2] 8a 41 [2] a1 6d [2] 8f 4f [2] 9b 54 [2] 94 4e [2] 8a 53 [2] 88 52 [2] 93 54 [2] 8f 53 [2] 93 7c }

  condition:
    any of them
}