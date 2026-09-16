rule TTP_XOR_QUAD_CurrentVersionRun_4154 {
  strings:
    $key_4154 = { 12 3b [2] 36 35 [2] 1d 19 [2] 33 3b [2] 27 20 [2] 28 3a [2] 36 27 [2] 34 26 [2] 2f 20 [2] 33 27 [2] 2f 08 }

  condition:
    any of them
}