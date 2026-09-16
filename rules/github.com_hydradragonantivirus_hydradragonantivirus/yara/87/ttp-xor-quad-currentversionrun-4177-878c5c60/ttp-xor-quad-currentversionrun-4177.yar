rule TTP_XOR_QUAD_CurrentVersionRun_4177 {
  strings:
    $key_4177 = { 12 18 [2] 36 16 [2] 1d 3a [2] 33 18 [2] 27 03 [2] 28 19 [2] 36 04 [2] 34 05 [2] 2f 03 [2] 33 04 [2] 2f 2b }

  condition:
    any of them
}