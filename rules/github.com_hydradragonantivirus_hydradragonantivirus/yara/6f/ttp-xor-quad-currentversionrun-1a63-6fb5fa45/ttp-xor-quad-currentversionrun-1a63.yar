rule TTP_XOR_QUAD_CurrentVersionRun_1a63 {
  strings:
    $key_1a63 = { 49 0c [2] 6d 02 [2] 46 2e [2] 68 0c [2] 7c 17 [2] 73 0d [2] 6d 10 [2] 6f 11 [2] 74 17 [2] 68 10 [2] 74 3f }

  condition:
    any of them
}