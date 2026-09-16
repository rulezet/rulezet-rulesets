rule TTP_XOR_QUAD_CurrentVersionRun_4178 {
  strings:
    $key_4178 = { 12 17 [2] 36 19 [2] 1d 35 [2] 33 17 [2] 27 0c [2] 28 16 [2] 36 0b [2] 34 0a [2] 2f 0c [2] 33 0b [2] 2f 24 }

  condition:
    any of them
}