rule TTP_XOR_QUAD_CurrentVersionRun_7363 {
  strings:
    $key_7363 = { 20 0c [2] 04 02 [2] 2f 2e [2] 01 0c [2] 15 17 [2] 1a 0d [2] 04 10 [2] 06 11 [2] 1d 17 [2] 01 10 [2] 1d 3f }

  condition:
    any of them
}