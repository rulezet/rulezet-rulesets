rule TTP_XOR_QUAD_CurrentVersionRun_4148 {
  strings:
    $key_4148 = { 12 27 [2] 36 29 [2] 1d 05 [2] 33 27 [2] 27 3c [2] 28 26 [2] 36 3b [2] 34 3a [2] 2f 3c [2] 33 3b [2] 2f 14 }

  condition:
    any of them
}