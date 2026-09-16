rule TTP_XOR_QUAD_CurrentVersionRun_4623 {
  strings:
    $key_4623 = { 15 4c [2] 31 42 [2] 1a 6e [2] 34 4c [2] 20 57 [2] 2f 4d [2] 31 50 [2] 33 51 [2] 28 57 [2] 34 50 [2] 28 7f }

  condition:
    any of them
}