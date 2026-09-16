rule TTP_XOR_QUAD_CurrentVersionRun_7164 {
  strings:
    $key_7164 = { 22 0b [2] 06 05 [2] 2d 29 [2] 03 0b [2] 17 10 [2] 18 0a [2] 06 17 [2] 04 16 [2] 1f 10 [2] 03 17 [2] 1f 38 }

  condition:
    any of them
}