rule TTP_XOR_QUAD_CurrentVersionRun_6659 {
  strings:
    $key_6659 = { 35 36 [2] 11 38 [2] 3a 14 [2] 14 36 [2] 00 2d [2] 0f 37 [2] 11 2a [2] 13 2b [2] 08 2d [2] 14 2a [2] 08 05 }

  condition:
    any of them
}