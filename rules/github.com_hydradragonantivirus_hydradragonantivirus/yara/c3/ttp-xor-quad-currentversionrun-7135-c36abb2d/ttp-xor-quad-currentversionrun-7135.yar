rule TTP_XOR_QUAD_CurrentVersionRun_7135 {
  strings:
    $key_7135 = { 22 5a [2] 06 54 [2] 2d 78 [2] 03 5a [2] 17 41 [2] 18 5b [2] 06 46 [2] 04 47 [2] 1f 41 [2] 03 46 [2] 1f 69 }

  condition:
    any of them
}