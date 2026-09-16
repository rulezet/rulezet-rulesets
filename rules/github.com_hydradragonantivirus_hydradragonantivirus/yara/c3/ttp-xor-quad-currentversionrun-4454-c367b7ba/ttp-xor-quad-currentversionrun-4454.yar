rule TTP_XOR_QUAD_CurrentVersionRun_4454 {
  strings:
    $key_4454 = { 17 3b [2] 33 35 [2] 18 19 [2] 36 3b [2] 22 20 [2] 2d 3a [2] 33 27 [2] 31 26 [2] 2a 20 [2] 36 27 [2] 2a 08 }

  condition:
    any of them
}