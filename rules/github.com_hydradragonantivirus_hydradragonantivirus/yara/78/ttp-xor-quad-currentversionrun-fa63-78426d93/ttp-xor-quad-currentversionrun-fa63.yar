rule TTP_XOR_QUAD_CurrentVersionRun_fa63 {
  strings:
    $key_fa63 = { a9 0c [2] 8d 02 [2] a6 2e [2] 88 0c [2] 9c 17 [2] 93 0d [2] 8d 10 [2] 8f 11 [2] 94 17 [2] 88 10 [2] 94 3f }

  condition:
    any of them
}