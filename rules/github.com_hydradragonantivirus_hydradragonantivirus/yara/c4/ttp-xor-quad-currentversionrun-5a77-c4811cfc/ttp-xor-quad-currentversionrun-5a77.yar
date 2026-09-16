rule TTP_XOR_QUAD_CurrentVersionRun_5a77 {
  strings:
    $key_5a77 = { 09 18 [2] 2d 16 [2] 06 3a [2] 28 18 [2] 3c 03 [2] 33 19 [2] 2d 04 [2] 2f 05 [2] 34 03 [2] 28 04 [2] 34 2b }

  condition:
    any of them
}