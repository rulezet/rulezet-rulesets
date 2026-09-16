rule TTP_XOR_QUAD_CurrentVersionRun_f573 {
  strings:
    $key_f573 = { a6 1c [2] 82 12 [2] a9 3e [2] 87 1c [2] 93 07 [2] 9c 1d [2] 82 00 [2] 80 01 [2] 9b 07 [2] 87 00 [2] 9b 2f }

  condition:
    any of them
}