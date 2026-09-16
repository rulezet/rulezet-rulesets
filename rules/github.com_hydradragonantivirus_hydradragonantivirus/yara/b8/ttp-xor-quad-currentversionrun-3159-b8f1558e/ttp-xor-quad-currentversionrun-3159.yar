rule TTP_XOR_QUAD_CurrentVersionRun_3159 {
  strings:
    $key_3159 = { 62 36 [2] 46 38 [2] 6d 14 [2] 43 36 [2] 57 2d [2] 58 37 [2] 46 2a [2] 44 2b [2] 5f 2d [2] 43 2a [2] 5f 05 }

  condition:
    any of them
}