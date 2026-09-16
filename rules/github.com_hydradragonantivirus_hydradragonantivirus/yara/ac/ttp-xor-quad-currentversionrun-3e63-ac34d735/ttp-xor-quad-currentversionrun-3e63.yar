rule TTP_XOR_QUAD_CurrentVersionRun_3e63 {
  strings:
    $key_3e63 = { 6d 0c [2] 49 02 [2] 62 2e [2] 4c 0c [2] 58 17 [2] 57 0d [2] 49 10 [2] 4b 11 [2] 50 17 [2] 4c 10 [2] 50 3f }

  condition:
    any of them
}