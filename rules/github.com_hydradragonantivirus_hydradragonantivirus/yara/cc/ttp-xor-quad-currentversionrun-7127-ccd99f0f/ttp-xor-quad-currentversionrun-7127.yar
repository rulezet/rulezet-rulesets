rule TTP_XOR_QUAD_CurrentVersionRun_7127 {
  strings:
    $key_7127 = { 22 48 [2] 06 46 [2] 2d 6a [2] 03 48 [2] 17 53 [2] 18 49 [2] 06 54 [2] 04 55 [2] 1f 53 [2] 03 54 [2] 1f 7b }

  condition:
    any of them
}