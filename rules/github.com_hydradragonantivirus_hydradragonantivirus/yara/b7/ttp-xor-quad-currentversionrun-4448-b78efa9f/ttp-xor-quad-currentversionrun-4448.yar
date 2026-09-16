rule TTP_XOR_QUAD_CurrentVersionRun_4448 {
  strings:
    $key_4448 = { 17 27 [2] 33 29 [2] 18 05 [2] 36 27 [2] 22 3c [2] 2d 26 [2] 33 3b [2] 31 3a [2] 2a 3c [2] 36 3b [2] 2a 14 }

  condition:
    any of them
}