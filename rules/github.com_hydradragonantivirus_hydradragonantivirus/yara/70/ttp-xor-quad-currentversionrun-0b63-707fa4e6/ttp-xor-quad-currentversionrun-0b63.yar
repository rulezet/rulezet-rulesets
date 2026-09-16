rule TTP_XOR_QUAD_CurrentVersionRun_0b63 {
  strings:
    $key_0b63 = { 58 0c [2] 7c 02 [2] 57 2e [2] 79 0c [2] 6d 17 [2] 62 0d [2] 7c 10 [2] 7e 11 [2] 65 17 [2] 79 10 [2] 65 3f }

  condition:
    any of them
}