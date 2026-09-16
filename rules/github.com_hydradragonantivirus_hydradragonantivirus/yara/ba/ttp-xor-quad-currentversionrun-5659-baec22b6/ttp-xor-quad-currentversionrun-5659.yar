rule TTP_XOR_QUAD_CurrentVersionRun_5659 {
  strings:
    $key_5659 = { 05 36 [2] 21 38 [2] 0a 14 [2] 24 36 [2] 30 2d [2] 3f 37 [2] 21 2a [2] 23 2b [2] 38 2d [2] 24 2a [2] 38 05 }

  condition:
    any of them
}