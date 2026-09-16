rule TTP_XOR_QUAD_CurrentVersionRun_4864 {
  strings:
    $key_4864 = { 1b 0b [2] 3f 05 [2] 14 29 [2] 3a 0b [2] 2e 10 [2] 21 0a [2] 3f 17 [2] 3d 16 [2] 26 10 [2] 3a 17 [2] 26 38 }

  condition:
    any of them
}