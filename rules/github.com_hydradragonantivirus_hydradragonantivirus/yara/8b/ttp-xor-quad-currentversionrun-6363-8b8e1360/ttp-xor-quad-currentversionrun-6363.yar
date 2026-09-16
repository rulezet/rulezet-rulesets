rule TTP_XOR_QUAD_CurrentVersionRun_6363 {
  strings:
    $key_6363 = { 30 0c [2] 14 02 [2] 3f 2e [2] 11 0c [2] 05 17 [2] 0a 0d [2] 14 10 [2] 16 11 [2] 0d 17 [2] 11 10 [2] 0d 3f }

  condition:
    any of them
}