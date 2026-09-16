rule TTP_XOR_QUAD_CurrentVersionRun_4847 {
  strings:
    $key_4847 = { 1b 28 [2] 3f 26 [2] 14 0a [2] 3a 28 [2] 2e 33 [2] 21 29 [2] 3f 34 [2] 3d 35 [2] 26 33 [2] 3a 34 [2] 26 1b }

  condition:
    any of them
}