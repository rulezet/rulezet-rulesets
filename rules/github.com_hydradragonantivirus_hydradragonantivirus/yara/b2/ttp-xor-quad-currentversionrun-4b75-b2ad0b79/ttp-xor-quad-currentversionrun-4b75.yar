rule TTP_XOR_QUAD_CurrentVersionRun_4b75 {
  strings:
    $key_4b75 = { 18 1a [2] 3c 14 [2] 17 38 [2] 39 1a [2] 2d 01 [2] 22 1b [2] 3c 06 [2] 3e 07 [2] 25 01 [2] 39 06 [2] 25 29 }

  condition:
    any of them
}