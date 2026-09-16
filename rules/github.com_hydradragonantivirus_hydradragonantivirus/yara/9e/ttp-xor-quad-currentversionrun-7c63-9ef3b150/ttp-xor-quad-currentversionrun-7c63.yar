rule TTP_XOR_QUAD_CurrentVersionRun_7c63 {
  strings:
    $key_7c63 = { 2f 0c [2] 0b 02 [2] 20 2e [2] 0e 0c [2] 1a 17 [2] 15 0d [2] 0b 10 [2] 09 11 [2] 12 17 [2] 0e 10 [2] 12 3f }

  condition:
    any of them
}