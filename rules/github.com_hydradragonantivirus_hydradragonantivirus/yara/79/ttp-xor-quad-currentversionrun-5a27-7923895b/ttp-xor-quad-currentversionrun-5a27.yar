rule TTP_XOR_QUAD_CurrentVersionRun_5a27 {
  strings:
    $key_5a27 = { 09 48 [2] 2d 46 [2] 06 6a [2] 28 48 [2] 3c 53 [2] 33 49 [2] 2d 54 [2] 2f 55 [2] 34 53 [2] 28 54 [2] 34 7b }

  condition:
    any of them
}