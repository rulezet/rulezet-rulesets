rule TTP_XOR_QUAD_CurrentVersionRun_2459 {
  strings:
    $key_2459 = { 77 36 [2] 53 38 [2] 78 14 [2] 56 36 [2] 42 2d [2] 4d 37 [2] 53 2a [2] 51 2b [2] 4a 2d [2] 56 2a [2] 4a 05 }

  condition:
    any of them
}