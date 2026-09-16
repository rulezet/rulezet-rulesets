rule TTP_XOR_QUAD_CurrentVersionRun_4119 {
  strings:
    $key_4119 = { 12 76 [2] 36 78 [2] 1d 54 [2] 33 76 [2] 27 6d [2] 28 77 [2] 36 6a [2] 34 6b [2] 2f 6d [2] 33 6a [2] 2f 45 }

  condition:
    any of them
}