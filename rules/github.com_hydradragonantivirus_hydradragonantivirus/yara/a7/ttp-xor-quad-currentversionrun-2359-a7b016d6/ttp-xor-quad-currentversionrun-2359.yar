rule TTP_XOR_QUAD_CurrentVersionRun_2359 {
  strings:
    $key_2359 = { 70 36 [2] 54 38 [2] 7f 14 [2] 51 36 [2] 45 2d [2] 4a 37 [2] 54 2a [2] 56 2b [2] 4d 2d [2] 51 2a [2] 4d 05 }

  condition:
    any of them
}