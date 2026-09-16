rule TTP_XOR_QUAD_CurrentVersionRun_4164 {
  strings:
    $key_4164 = { 12 0b [2] 36 05 [2] 1d 29 [2] 33 0b [2] 27 10 [2] 28 0a [2] 36 17 [2] 34 16 [2] 2f 10 [2] 33 17 [2] 2f 38 }

  condition:
    any of them
}