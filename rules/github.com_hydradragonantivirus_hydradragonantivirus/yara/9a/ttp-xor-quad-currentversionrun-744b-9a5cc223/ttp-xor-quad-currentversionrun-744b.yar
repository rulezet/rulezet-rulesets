rule TTP_XOR_QUAD_CurrentVersionRun_744b {
  strings:
    $key_744b = { 27 24 [2] 03 2a [2] 28 06 [2] 06 24 [2] 12 3f [2] 1d 25 [2] 03 38 [2] 01 39 [2] 1a 3f [2] 06 38 [2] 1a 17 }

  condition:
    any of them
}