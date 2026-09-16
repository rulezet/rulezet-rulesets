rule TTP_XOR_QUAD_CurrentVersionRun_0c63 {
  strings:
    $key_0c63 = { 5f 0c [2] 7b 02 [2] 50 2e [2] 7e 0c [2] 6a 17 [2] 65 0d [2] 7b 10 [2] 79 11 [2] 62 17 [2] 7e 10 [2] 62 3f }

  condition:
    any of them
}