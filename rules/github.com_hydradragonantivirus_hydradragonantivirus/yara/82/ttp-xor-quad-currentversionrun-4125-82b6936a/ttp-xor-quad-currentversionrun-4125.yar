rule TTP_XOR_QUAD_CurrentVersionRun_4125 {
  strings:
    $key_4125 = { 12 4a [2] 36 44 [2] 1d 68 [2] 33 4a [2] 27 51 [2] 28 4b [2] 36 56 [2] 34 57 [2] 2f 51 [2] 33 56 [2] 2f 79 }

  condition:
    any of them
}