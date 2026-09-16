rule TTP_XOR_QUAD_CurrentVersionRun_1c63 {
  strings:
    $key_1c63 = { 4f 0c [2] 6b 02 [2] 40 2e [2] 6e 0c [2] 7a 17 [2] 75 0d [2] 6b 10 [2] 69 11 [2] 72 17 [2] 6e 10 [2] 72 3f }

  condition:
    any of them
}