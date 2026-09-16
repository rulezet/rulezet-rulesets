rule TTP_XOR_QUAD_CurrentVersionRun_5477 {
  strings:
    $key_5477 = { 07 18 [2] 23 16 [2] 08 3a [2] 26 18 [2] 32 03 [2] 3d 19 [2] 23 04 [2] 21 05 [2] 3a 03 [2] 26 04 [2] 3a 2b }

  condition:
    any of them
}