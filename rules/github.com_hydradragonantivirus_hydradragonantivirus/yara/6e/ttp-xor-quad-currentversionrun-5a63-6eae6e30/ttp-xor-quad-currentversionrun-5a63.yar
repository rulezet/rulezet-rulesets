rule TTP_XOR_QUAD_CurrentVersionRun_5a63 {
  strings:
    $key_5a63 = { 09 0c [2] 2d 02 [2] 06 2e [2] 28 0c [2] 3c 17 [2] 33 0d [2] 2d 10 [2] 2f 11 [2] 34 17 [2] 28 10 [2] 34 3f }

  condition:
    any of them
}