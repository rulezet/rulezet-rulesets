rule TTP_XOR_QUAD_CurrentVersionRun_5445 {
  strings:
    $key_5445 = { 07 2a [2] 23 24 [2] 08 08 [2] 26 2a [2] 32 31 [2] 3d 2b [2] 23 36 [2] 21 37 [2] 3a 31 [2] 26 36 [2] 3a 19 }

  condition:
    any of them
}