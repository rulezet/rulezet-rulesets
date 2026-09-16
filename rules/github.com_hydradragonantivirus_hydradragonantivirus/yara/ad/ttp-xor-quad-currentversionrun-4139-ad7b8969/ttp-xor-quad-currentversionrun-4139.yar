rule TTP_XOR_QUAD_CurrentVersionRun_4139 {
  strings:
    $key_4139 = { 12 56 [2] 36 58 [2] 1d 74 [2] 33 56 [2] 27 4d [2] 28 57 [2] 36 4a [2] 34 4b [2] 2f 4d [2] 33 4a [2] 2f 65 }

  condition:
    any of them
}