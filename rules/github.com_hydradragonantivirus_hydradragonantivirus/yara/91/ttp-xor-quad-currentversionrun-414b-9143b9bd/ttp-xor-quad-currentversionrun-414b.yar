rule TTP_XOR_QUAD_CurrentVersionRun_414b {
  strings:
    $key_414b = { 12 24 [2] 36 2a [2] 1d 06 [2] 33 24 [2] 27 3f [2] 28 25 [2] 36 38 [2] 34 39 [2] 2f 3f [2] 33 38 [2] 2f 17 }

  condition:
    any of them
}