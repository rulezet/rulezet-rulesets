rule TTP_XOR_QUAD_CurrentVersionRun_4324 {
  strings:
    $key_4324 = { 10 4b [2] 34 45 [2] 1f 69 [2] 31 4b [2] 25 50 [2] 2a 4a [2] 34 57 [2] 36 56 [2] 2d 50 [2] 31 57 [2] 2d 78 }

  condition:
    any of them
}