rule TTP_XOR_QUAD_CurrentVersionRun_4f77 {
  strings:
    $key_4f77 = { 1c 18 [2] 38 16 [2] 13 3a [2] 3d 18 [2] 29 03 [2] 26 19 [2] 38 04 [2] 3a 05 [2] 21 03 [2] 3d 04 [2] 21 2b }

  condition:
    any of them
}