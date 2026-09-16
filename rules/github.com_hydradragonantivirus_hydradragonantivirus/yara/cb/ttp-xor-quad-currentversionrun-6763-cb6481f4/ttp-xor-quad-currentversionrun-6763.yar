rule TTP_XOR_QUAD_CurrentVersionRun_6763 {
  strings:
    $key_6763 = { 34 0c [2] 10 02 [2] 3b 2e [2] 15 0c [2] 01 17 [2] 0e 0d [2] 10 10 [2] 12 11 [2] 09 17 [2] 15 10 [2] 09 3f }

  condition:
    any of them
}