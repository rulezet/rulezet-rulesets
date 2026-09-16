rule TTP_XOR_QUAD_CurrentVersionRun_5141 {
  strings:
    $key_5141 = { 02 2e [2] 26 20 [2] 0d 0c [2] 23 2e [2] 37 35 [2] 38 2f [2] 26 32 [2] 24 33 [2] 3f 35 [2] 23 32 [2] 3f 1d }

  condition:
    any of them
}