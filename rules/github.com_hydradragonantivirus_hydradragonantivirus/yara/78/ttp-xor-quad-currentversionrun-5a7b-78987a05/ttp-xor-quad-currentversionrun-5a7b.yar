rule TTP_XOR_QUAD_CurrentVersionRun_5a7b {
  strings:
    $key_5a7b = { 09 14 [2] 2d 1a [2] 06 36 [2] 28 14 [2] 3c 0f [2] 33 15 [2] 2d 08 [2] 2f 09 [2] 34 0f [2] 28 08 [2] 34 27 }

  condition:
    any of them
}