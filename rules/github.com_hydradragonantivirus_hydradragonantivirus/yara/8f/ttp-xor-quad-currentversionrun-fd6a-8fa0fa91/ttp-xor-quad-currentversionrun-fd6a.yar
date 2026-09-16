rule TTP_XOR_QUAD_CurrentVersionRun_fd6a {
  strings:
    $key_fd6a = { ae 05 [2] 8a 0b [2] a1 27 [2] 8f 05 [2] 9b 1e [2] 94 04 [2] 8a 19 [2] 88 18 [2] 93 1e [2] 8f 19 [2] 93 36 }

  condition:
    any of them
}