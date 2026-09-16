rule TTP_XOR_QUAD_CurrentVersionRun_6f63 {
  strings:
    $key_6f63 = { 3c 0c [2] 18 02 [2] 33 2e [2] 1d 0c [2] 09 17 [2] 06 0d [2] 18 10 [2] 1a 11 [2] 01 17 [2] 1d 10 [2] 01 3f }

  condition:
    any of them
}