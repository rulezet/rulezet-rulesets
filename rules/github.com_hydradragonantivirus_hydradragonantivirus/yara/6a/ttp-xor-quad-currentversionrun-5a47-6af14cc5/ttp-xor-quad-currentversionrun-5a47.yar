rule TTP_XOR_QUAD_CurrentVersionRun_5a47 {
  strings:
    $key_5a47 = { 09 28 [2] 2d 26 [2] 06 0a [2] 28 28 [2] 3c 33 [2] 33 29 [2] 2d 34 [2] 2f 35 [2] 34 33 [2] 28 34 [2] 34 1b }

  condition:
    any of them
}