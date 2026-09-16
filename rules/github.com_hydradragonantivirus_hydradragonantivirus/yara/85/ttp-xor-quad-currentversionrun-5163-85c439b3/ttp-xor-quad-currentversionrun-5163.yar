rule TTP_XOR_QUAD_CurrentVersionRun_5163 {
  strings:
    $key_5163 = { 02 0c [2] 26 02 [2] 0d 2e [2] 23 0c [2] 37 17 [2] 38 0d [2] 26 10 [2] 24 11 [2] 3f 17 [2] 23 10 [2] 3f 3f }

  condition:
    any of them
}