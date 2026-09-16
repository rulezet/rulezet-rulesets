rule TTP_XOR_QUAD_CurrentVersionRun_1b63 {
  strings:
    $key_1b63 = { 48 0c [2] 6c 02 [2] 47 2e [2] 69 0c [2] 7d 17 [2] 72 0d [2] 6c 10 [2] 6e 11 [2] 75 17 [2] 69 10 [2] 75 3f }

  condition:
    any of them
}