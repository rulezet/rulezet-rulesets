rule TTP_XOR_QUAD_CurrentVersionRun_4167 {
  strings:
    $key_4167 = { 12 08 [2] 36 06 [2] 1d 2a [2] 33 08 [2] 27 13 [2] 28 09 [2] 36 14 [2] 34 15 [2] 2f 13 [2] 33 14 [2] 2f 3b }

  condition:
    any of them
}