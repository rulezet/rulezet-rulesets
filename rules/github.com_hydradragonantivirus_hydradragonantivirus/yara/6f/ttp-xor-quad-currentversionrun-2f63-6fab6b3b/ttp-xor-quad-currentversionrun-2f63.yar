rule TTP_XOR_QUAD_CurrentVersionRun_2f63 {
  strings:
    $key_2f63 = { 7c 0c [2] 58 02 [2] 73 2e [2] 5d 0c [2] 49 17 [2] 46 0d [2] 58 10 [2] 5a 11 [2] 41 17 [2] 5d 10 [2] 41 3f }

  condition:
    any of them
}