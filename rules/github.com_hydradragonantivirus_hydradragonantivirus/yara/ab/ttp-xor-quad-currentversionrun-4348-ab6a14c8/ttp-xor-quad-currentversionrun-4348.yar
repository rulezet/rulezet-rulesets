rule TTP_XOR_QUAD_CurrentVersionRun_4348 {
  strings:
    $key_4348 = { 10 27 [2] 34 29 [2] 1f 05 [2] 31 27 [2] 25 3c [2] 2a 26 [2] 34 3b [2] 36 3a [2] 2d 3c [2] 31 3b [2] 2d 14 }

  condition:
    any of them
}