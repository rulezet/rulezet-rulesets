rule TTP_XOR_QUAD_CurrentVersionRun_6c63 {
  strings:
    $key_6c63 = { 3f 0c [2] 1b 02 [2] 30 2e [2] 1e 0c [2] 0a 17 [2] 05 0d [2] 1b 10 [2] 19 11 [2] 02 17 [2] 1e 10 [2] 02 3f }

  condition:
    any of them
}