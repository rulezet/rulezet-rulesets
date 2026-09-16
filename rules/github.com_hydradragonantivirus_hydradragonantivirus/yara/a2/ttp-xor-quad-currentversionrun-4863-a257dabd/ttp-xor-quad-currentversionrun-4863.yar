rule TTP_XOR_QUAD_CurrentVersionRun_4863 {
  strings:
    $key_4863 = { 1b 0c [2] 3f 02 [2] 14 2e [2] 3a 0c [2] 2e 17 [2] 21 0d [2] 3f 10 [2] 3d 11 [2] 26 17 [2] 3a 10 [2] 26 3f }

  condition:
    any of them
}