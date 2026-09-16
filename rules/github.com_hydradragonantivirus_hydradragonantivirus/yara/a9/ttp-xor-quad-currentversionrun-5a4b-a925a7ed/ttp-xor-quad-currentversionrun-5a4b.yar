rule TTP_XOR_QUAD_CurrentVersionRun_5a4b {
  strings:
    $key_5a4b = { 09 24 [2] 2d 2a [2] 06 06 [2] 28 24 [2] 3c 3f [2] 33 25 [2] 2d 38 [2] 2f 39 [2] 34 3f [2] 28 38 [2] 34 17 }

  condition:
    any of them
}