rule TTP_XOR_QUAD_CurrentVersionRun_7154 {
  strings:
    $key_7154 = { 22 3b [2] 06 35 [2] 2d 19 [2] 03 3b [2] 17 20 [2] 18 3a [2] 06 27 [2] 04 26 [2] 1f 20 [2] 03 27 [2] 1f 08 }

  condition:
    any of them
}