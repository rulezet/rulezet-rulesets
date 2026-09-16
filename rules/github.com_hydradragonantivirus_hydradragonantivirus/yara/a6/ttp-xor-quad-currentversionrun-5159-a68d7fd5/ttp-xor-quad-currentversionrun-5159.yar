rule TTP_XOR_QUAD_CurrentVersionRun_5159 {
  strings:
    $key_5159 = { 02 36 [2] 26 38 [2] 0d 14 [2] 23 36 [2] 37 2d [2] 38 37 [2] 26 2a [2] 24 2b [2] 3f 2d [2] 23 2a [2] 3f 05 }

  condition:
    any of them
}