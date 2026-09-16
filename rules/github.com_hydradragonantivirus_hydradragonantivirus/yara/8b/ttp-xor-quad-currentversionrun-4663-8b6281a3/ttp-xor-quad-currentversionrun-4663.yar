rule TTP_XOR_QUAD_CurrentVersionRun_4663 {
  strings:
    $key_4663 = { 15 0c [2] 31 02 [2] 1a 2e [2] 34 0c [2] 20 17 [2] 2f 0d [2] 31 10 [2] 33 11 [2] 28 17 [2] 34 10 [2] 28 3f }

  condition:
    any of them
}