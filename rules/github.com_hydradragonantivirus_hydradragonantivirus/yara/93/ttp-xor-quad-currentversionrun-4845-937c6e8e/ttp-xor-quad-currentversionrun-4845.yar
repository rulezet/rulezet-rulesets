rule TTP_XOR_QUAD_CurrentVersionRun_4845 {
  strings:
    $key_4845 = { 1b 2a [2] 3f 24 [2] 14 08 [2] 3a 2a [2] 2e 31 [2] 21 2b [2] 3f 36 [2] 3d 37 [2] 26 31 [2] 3a 36 [2] 26 19 }

  condition:
    any of them
}