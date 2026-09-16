rule TTP_XOR_QUAD_CurrentVersionRun_fd0d {
  strings:
    $key_fd0d = { ae 62 [2] 8a 6c [2] a1 40 [2] 8f 62 [2] 9b 79 [2] 94 63 [2] 8a 7e [2] 88 7f [2] 93 79 [2] 8f 7e [2] 93 51 }

  condition:
    any of them
}