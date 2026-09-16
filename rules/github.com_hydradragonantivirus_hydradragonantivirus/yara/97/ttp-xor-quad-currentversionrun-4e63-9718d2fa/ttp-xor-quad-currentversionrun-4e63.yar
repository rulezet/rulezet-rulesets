rule TTP_XOR_QUAD_CurrentVersionRun_4e63 {
  strings:
    $key_4e63 = { 1d 0c [2] 39 02 [2] 12 2e [2] 3c 0c [2] 28 17 [2] 27 0d [2] 39 10 [2] 3b 11 [2] 20 17 [2] 3c 10 [2] 20 3f }

  condition:
    any of them
}