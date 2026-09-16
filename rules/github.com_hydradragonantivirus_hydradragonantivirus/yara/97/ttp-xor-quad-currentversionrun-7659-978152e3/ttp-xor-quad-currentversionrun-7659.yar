rule TTP_XOR_QUAD_CurrentVersionRun_7659 {
  strings:
    $key_7659 = { 25 36 [2] 01 38 [2] 2a 14 [2] 04 36 [2] 10 2d [2] 1f 37 [2] 01 2a [2] 03 2b [2] 18 2d [2] 04 2a [2] 18 05 }

  condition:
    any of them
}