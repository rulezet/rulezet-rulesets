rule TTP_XOR_QUAD_CurrentVersionRun_4134 {
  strings:
    $key_4134 = { 12 5b [2] 36 55 [2] 1d 79 [2] 33 5b [2] 27 40 [2] 28 5a [2] 36 47 [2] 34 46 [2] 2f 40 [2] 33 47 [2] 2f 68 }

  condition:
    any of them
}