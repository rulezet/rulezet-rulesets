rule TTP_XOR_QUAD_CurrentVersionRun_4329 {
  strings:
    $key_4329 = { 10 46 [2] 34 48 [2] 1f 64 [2] 31 46 [2] 25 5d [2] 2a 47 [2] 34 5a [2] 36 5b [2] 2d 5d [2] 31 5a [2] 2d 75 }

  condition:
    any of them
}