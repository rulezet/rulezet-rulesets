rule TTP_XOR_QUAD_CurrentVersionRun_4848 {
  strings:
    $key_4848 = { 1b 27 [2] 3f 29 [2] 14 05 [2] 3a 27 [2] 2e 3c [2] 21 26 [2] 3f 3b [2] 3d 3a [2] 26 3c [2] 3a 3b [2] 26 14 }

  condition:
    any of them
}