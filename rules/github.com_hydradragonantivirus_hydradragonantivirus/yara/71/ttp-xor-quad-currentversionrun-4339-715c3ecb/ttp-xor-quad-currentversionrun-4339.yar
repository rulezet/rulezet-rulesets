rule TTP_XOR_QUAD_CurrentVersionRun_4339 {
  strings:
    $key_4339 = { 10 56 [2] 34 58 [2] 1f 74 [2] 31 56 [2] 25 4d [2] 2a 57 [2] 34 4a [2] 36 4b [2] 2d 4d [2] 31 4a [2] 2d 65 }

  condition:
    any of them
}