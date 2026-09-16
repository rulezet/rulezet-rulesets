rule TTP_XOR_QUAD_CurrentVersionRun_3379 {
  strings:
    $key_3379 = { 60 16 [2] 44 18 [2] 6f 34 [2] 41 16 [2] 55 0d [2] 5a 17 [2] 44 0a [2] 46 0b [2] 5d 0d [2] 41 0a [2] 5d 25 }

  condition:
    any of them
}