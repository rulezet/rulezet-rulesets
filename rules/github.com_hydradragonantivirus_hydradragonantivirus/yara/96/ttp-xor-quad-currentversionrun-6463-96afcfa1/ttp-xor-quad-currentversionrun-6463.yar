rule TTP_XOR_QUAD_CurrentVersionRun_6463 {
  strings:
    $key_6463 = { 37 0c [2] 13 02 [2] 38 2e [2] 16 0c [2] 02 17 [2] 0d 0d [2] 13 10 [2] 11 11 [2] 0a 17 [2] 16 10 [2] 0a 3f }

  condition:
    any of them
}