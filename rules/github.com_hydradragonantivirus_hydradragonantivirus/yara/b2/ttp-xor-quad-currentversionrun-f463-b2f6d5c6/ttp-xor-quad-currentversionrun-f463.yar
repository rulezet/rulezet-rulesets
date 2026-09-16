rule TTP_XOR_QUAD_CurrentVersionRun_f463 {
  strings:
    $key_f463 = { a7 0c [2] 83 02 [2] a8 2e [2] 86 0c [2] 92 17 [2] 9d 0d [2] 83 10 [2] 81 11 [2] 9a 17 [2] 86 10 [2] 9a 3f }

  condition:
    any of them
}