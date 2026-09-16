rule TTP_XOR_QUAD_CurrentVersionRun_434b {
  strings:
    $key_434b = { 10 24 [2] 34 2a [2] 1f 06 [2] 31 24 [2] 25 3f [2] 2a 25 [2] 34 38 [2] 36 39 [2] 2d 3f [2] 31 38 [2] 2d 17 }

  condition:
    any of them
}