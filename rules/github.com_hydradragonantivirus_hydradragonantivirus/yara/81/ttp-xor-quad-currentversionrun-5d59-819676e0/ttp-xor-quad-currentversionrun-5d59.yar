rule TTP_XOR_QUAD_CurrentVersionRun_5d59 {
  strings:
    $key_5d59 = { 0e 36 [2] 2a 38 [2] 01 14 [2] 2f 36 [2] 3b 2d [2] 34 37 [2] 2a 2a [2] 28 2b [2] 33 2d [2] 2f 2a [2] 33 05 }

  condition:
    any of them
}