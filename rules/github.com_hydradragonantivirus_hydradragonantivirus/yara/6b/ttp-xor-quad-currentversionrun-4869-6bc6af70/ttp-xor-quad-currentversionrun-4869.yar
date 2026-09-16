rule TTP_XOR_QUAD_CurrentVersionRun_4869 {
  strings:
    $key_4869 = { 1b 06 [2] 3f 08 [2] 14 24 [2] 3a 06 [2] 2e 1d [2] 21 07 [2] 3f 1a [2] 3d 1b [2] 26 1d [2] 3a 1a [2] 26 35 }

  condition:
    any of them
}