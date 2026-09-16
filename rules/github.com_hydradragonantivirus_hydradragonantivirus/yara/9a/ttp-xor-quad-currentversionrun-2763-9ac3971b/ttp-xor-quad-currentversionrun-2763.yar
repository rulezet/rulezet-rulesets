rule TTP_XOR_QUAD_CurrentVersionRun_2763 {
  strings:
    $key_2763 = { 74 0c [2] 50 02 [2] 7b 2e [2] 55 0c [2] 41 17 [2] 4e 0d [2] 50 10 [2] 52 11 [2] 49 17 [2] 55 10 [2] 49 3f }

  condition:
    any of them
}