rule TTP_XOR_QUAD_CurrentVersionRun_74fb {
  strings:
    $key_74fb = { 27 94 [2] 03 9a [2] 28 b6 [2] 06 94 [2] 12 8f [2] 1d 95 [2] 03 88 [2] 01 89 [2] 1a 8f [2] 06 88 [2] 1a a7 }

  condition:
    any of them
}