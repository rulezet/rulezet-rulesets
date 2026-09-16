rule TTP_XOR_QUAD_CurrentVersionRun_5a56 {
  strings:
    $key_5a56 = { 09 39 [2] 2d 37 [2] 06 1b [2] 28 39 [2] 3c 22 [2] 33 38 [2] 2d 25 [2] 2f 24 [2] 34 22 [2] 28 25 [2] 34 0a }

  condition:
    any of them
}