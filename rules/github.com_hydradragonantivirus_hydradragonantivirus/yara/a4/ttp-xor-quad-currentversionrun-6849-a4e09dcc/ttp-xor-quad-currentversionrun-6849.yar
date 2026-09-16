rule TTP_XOR_QUAD_CurrentVersionRun_6849 {
  strings:
    $key_6849 = { 3b 26 [2] 1f 28 [2] 34 04 [2] 1a 26 [2] 0e 3d [2] 01 27 [2] 1f 3a [2] 1d 3b [2] 06 3d [2] 1a 3a [2] 06 15 }

  condition:
    any of them
}