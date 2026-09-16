rule TTP_XOR_QUAD_CurrentVersionRun_7563 {
  strings:
    $key_7563 = { 26 0c [2] 02 02 [2] 29 2e [2] 07 0c [2] 13 17 [2] 1c 0d [2] 02 10 [2] 00 11 [2] 1b 17 [2] 07 10 [2] 1b 3f }

  condition:
    any of them
}