rule TTP_XOR_QUAD_CurrentVersionRun_4477 {
  strings:
    $key_4477 = { 17 18 [2] 33 16 [2] 18 3a [2] 36 18 [2] 22 03 [2] 2d 19 [2] 33 04 [2] 31 05 [2] 2a 03 [2] 36 04 [2] 2a 2b }

  condition:
    any of them
}