rule TTP_XOR_QUAD_CurrentVersionRun_5a1b {
  strings:
    $key_5a1b = { 09 74 [2] 2d 7a [2] 06 56 [2] 28 74 [2] 3c 6f [2] 33 75 [2] 2d 68 [2] 2f 69 [2] 34 6f [2] 28 68 [2] 34 47 }

  condition:
    any of them
}