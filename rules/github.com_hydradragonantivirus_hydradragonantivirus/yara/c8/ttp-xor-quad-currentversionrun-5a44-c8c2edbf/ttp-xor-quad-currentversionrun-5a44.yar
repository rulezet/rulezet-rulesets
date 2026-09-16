rule TTP_XOR_QUAD_CurrentVersionRun_5a44 {
  strings:
    $key_5a44 = { 09 2b [2] 2d 25 [2] 06 09 [2] 28 2b [2] 3c 30 [2] 33 2a [2] 2d 37 [2] 2f 36 [2] 34 30 [2] 28 37 [2] 34 18 }

  condition:
    any of them
}