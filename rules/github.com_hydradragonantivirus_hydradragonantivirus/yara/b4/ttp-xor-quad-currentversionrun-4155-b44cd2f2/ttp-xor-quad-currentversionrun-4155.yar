rule TTP_XOR_QUAD_CurrentVersionRun_4155 {
  strings:
    $key_4155 = { 12 3a [2] 36 34 [2] 1d 18 [2] 33 3a [2] 27 21 [2] 28 3b [2] 36 26 [2] 34 27 [2] 2f 21 [2] 33 26 [2] 2f 09 }

  condition:
    any of them
}