rule TTP_XOR_QUAD_CurrentVersionRun_5d63 {
  strings:
    $key_5d63 = { 0e 0c [2] 2a 02 [2] 01 2e [2] 2f 0c [2] 3b 17 [2] 34 0d [2] 2a 10 [2] 28 11 [2] 33 17 [2] 2f 10 [2] 33 3f }

  condition:
    any of them
}