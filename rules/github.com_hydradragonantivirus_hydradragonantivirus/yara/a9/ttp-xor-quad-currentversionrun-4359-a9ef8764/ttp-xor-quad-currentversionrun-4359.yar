rule TTP_XOR_QUAD_CurrentVersionRun_4359 {
  strings:
    $key_4359 = { 10 36 [2] 34 38 [2] 1f 14 [2] 31 36 [2] 25 2d [2] 2a 37 [2] 34 2a [2] 36 2b [2] 2d 2d [2] 31 2a [2] 2d 05 }

  condition:
    any of them
}