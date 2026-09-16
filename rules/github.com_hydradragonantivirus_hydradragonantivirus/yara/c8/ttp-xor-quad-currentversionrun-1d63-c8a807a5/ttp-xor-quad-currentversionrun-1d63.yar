rule TTP_XOR_QUAD_CurrentVersionRun_1d63 {
  strings:
    $key_1d63 = { 4e 0c [2] 6a 02 [2] 41 2e [2] 6f 0c [2] 7b 17 [2] 74 0d [2] 6a 10 [2] 68 11 [2] 73 17 [2] 6f 10 [2] 73 3f }

  condition:
    any of them
}