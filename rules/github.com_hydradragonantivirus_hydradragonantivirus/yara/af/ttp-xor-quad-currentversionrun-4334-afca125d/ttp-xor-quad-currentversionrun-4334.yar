rule TTP_XOR_QUAD_CurrentVersionRun_4334 {
  strings:
    $key_4334 = { 10 5b [2] 34 55 [2] 1f 79 [2] 31 5b [2] 25 40 [2] 2a 5a [2] 34 47 [2] 36 46 [2] 2d 40 [2] 31 47 [2] 2d 68 }

  condition:
    any of them
}